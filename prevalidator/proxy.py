"""FastAPI Prevalidator Proxy speaking standard OpenAI `/v1/chat/completions` and Anthropic `/v1/messages`, plus Directory Batch Prevalidation and Unified Operator Dashboard."""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from engine.directory_bridge import (
    compute_bytes_sha256_hex,
    discover_selectable_drives_and_directories,
    iter_scannable_files,
    iter_scannable_files_unbounded,
    resolve_pc_directory_path,
)
from engine.storage_connectors import is_enterprise_store_uri
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from registry.signing import Keyring, compute_file_sha256


def _extract_last_user_text(payload: dict[str, Any]) -> str:
    messages = payload.get("messages", [])
    for msg in reversed(messages):
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


async def _mock_openai_sse_stream(model: str, text: str) -> AsyncIterator[bytes]:
    chunk_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    words = [f"[Gateway Ack ({model})]:", *text.split()[:25]]
    for word in words:
        data = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{"index": 0, "delta": {"content": word + " "}, "finish_reason": None}],
        }
        yield f"data: {json.dumps(data)}\n\n".encode("utf-8")
    done_chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    yield f"data: {json.dumps(done_chunk)}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


async def _mock_anthropic_sse_stream(model: str, text: str) -> AsyncIterator[bytes]:
    msg_id = f"msg_{uuid.uuid4().hex[:12]}"
    start_evt = {
        "type": "message_start",
        "message": {"id": msg_id, "type": "message", "role": "assistant", "model": model, "content": []},
    }
    yield f"event: message_start\ndata: {json.dumps(start_evt)}\n\n".encode("utf-8")
    delta_evt = {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": f"[Anthropic Gateway Ack ({model})]: {text[:160]}"},
    }
    yield f"event: content_block_delta\ndata: {json.dumps(delta_evt)}\n\n".encode("utf-8")
    stop_evt = {"type": "message_stop"}
    yield f"event: message_stop\ndata: {json.dumps(stop_evt)}\n\n".encode("utf-8")


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <link rel="icon" type="image/png" href="/assets/g1-logo.png" />
  <title>G1 Docket by G1163RT Security Labs | Cryptographic Proof Of Data &amp; AI Prevalidator</title>
  <style>
    :root { --bg: #0b1120; --panel: #1e293b; --panel2: #0f172a; --border: #334155; --text: #f8fafc; --muted: #94a3b8; --accent: #10b981; --warn: #f59e0b; --danger: #ef4444; --info: #3b82f6; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
    body { margin: 0; background: var(--bg); color: var(--text); padding: 20px 28px; display: flex; flex-direction: column; min-height: 100vh; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 20px; }
    .brand-lockup { display: flex; align-items: center; gap: 16px; }
    .brand-logo { width: 52px; height: 52px; border-radius: 50%; object-fit: cover; border: 2px solid #475569; box-shadow: 0 0 14px rgba(59,130,246,0.35); background: #ffffff; }
    h1 { margin: 0; font-size: 24px; letter-spacing: 0.3px; display: flex; align-items: center; gap: 12px; }
    .brand-lab-tag { font-size: 12px; font-weight: 600; color: #93c5fd; letter-spacing: 0.6px; text-transform: uppercase; }
    footer { margin-top: auto; padding-top: 18px; padding-bottom: 8px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; color: var(--muted); font-size: 12.5px; }
    .footer-brand { display: flex; align-items: center; gap: 10px; }
    .footer-logo { width: 26px; height: 26px; border-radius: 50%; object-fit: cover; border: 1px solid #475569; background: #ffffff; }
    .badge { padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; display: inline-block; }
    .badge-Public, .badge-PASS { background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid rgba(16,185,129,0.4); }
    .badge-Internal { background: rgba(59,130,246,0.2); color: #60a5fa; border: 1px solid rgba(59,130,246,0.4); }
    .badge-Confidential, .badge-STRIP { background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); }
    .badge-Restricted, .badge-FAIL { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.4); }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; margin-bottom: 20px; }
    .card h2 { margin-top: 0; font-size: 16px; color: #e2e8f0; border-bottom: 1px solid var(--border); padding-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .score-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 14px 0; }
    .score-box { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; text-align: center; }
    .score-box .num { font-size: 26px; font-weight: 800; margin-top: 4px; }
    .score-box .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .english-verdict { background: #0f172a; border: 1px solid #475569; border-left: 5px solid var(--accent); border-radius: 8px; padding: 14px 16px; margin-bottom: 14px; font-size: 14.5px; line-height: 1.5; color: #f1f5f9; }
    .english-verdict.has-failures { border-left-color: var(--danger); background: rgba(239,68,68,0.08); }
    table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11.5px; color: #cbd5e1; }
    .btn { background: var(--info); color: white; border: none; padding: 9px 15px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; display: inline-flex; align-items: center; gap: 6px; }
    .btn:hover { opacity: 0.92; }
    .btn-green { background: var(--accent); color: #052e16; }
    .btn-amber { background: var(--warn); color: #451a03; }
    .btn-dark { background: #334155; color: #f8fafc; }
    textarea, select, input[type="text"] { width: 100%; background: var(--panel2); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-size: 13px; margin-bottom: 10px; font-family: ui-monospace, monospace; }
    pre { background: #090d16; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; border: 1px solid var(--border); margin: 0; white-space: pre-wrap; }
    .links a { color: #60a5fa; text-decoration: none; margin-left: 14px; font-size: 13px; }
    .folder-browser { display: none; background: #090d16; border: 1px solid #3b82f6; border-radius: 8px; padding: 14px; margin-top: 12px; }
    .folder-item { display: inline-block; background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 6px 12px; margin: 4px; cursor: pointer; font-size: 12.5px; color: #93c5fd; }
    .folder-item:hover { background: #334155; color: #ffffff; }
    .file-link { color: #38bdf8; cursor: pointer; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; padding: 3px 7px; border-radius: 5px; transition: background 0.15s, color 0.15s, border-color 0.15s; border: 1px solid rgba(56, 189, 248, 0.25); background: rgba(15, 23, 42, 0.6); }
    .file-link:hover { background: rgba(56, 189, 248, 0.18); border-color: #38bdf8; color: #bae6fd; text-decoration: underline; }
    .inspector-overlay { display: none; position: fixed; inset: 0; background: rgba(2, 6, 23, 0.82); backdrop-filter: blur(4px); z-index: 9999; align-items: center; justify-content: center; padding: 20px; }
    .inspector-modal { background: #0f172a; border: 2px solid #0284c7; border-radius: 12px; width: 100%; max-width: 1060px; max-height: 90vh; display: flex; flex-direction: column; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.85); overflow: hidden; }
    .inspector-header { padding: 16px 22px; background: linear-gradient(90deg, #091526 0%, #1e293b 100%); border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
    .inspector-body { padding: 18px 22px; overflow-y: auto; display: flex; flex-direction: column; gap: 14px; }
    .inspector-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .inspector-section { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 14px; }
    .inspector-section h3 { margin: 0 0 10px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.6px; color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 6px; display: flex; justify-content: space-between; align-items: center; }
    .kv-row { display: grid; grid-template-columns: 155px 1fr; gap: 8px; padding: 5px 0; border-bottom: 1px dashed rgba(51, 65, 85, 0.55); font-size: 12.5px; align-items: baseline; }
    .kv-row:last-child { border-bottom: none; }
    .kv-label { color: var(--muted); font-weight: 600; font-size: 11.5px; }
    .kv-val { color: #f8fafc; word-break: break-all; }
  </style>
</head>
<body>
  <header>
    <div class="brand-lockup">
      <img src="/assets/g1-logo.png" alt="G1 Logo" class="brand-logo" />
      <div>
        <h1>
          <span>G1 Docket</span>
          <span class="brand-lab-tag">by G1163RT Security Labs</span>
          <span id="modeBadge" class="badge badge-Public">ENFORCE MODE</span>
        </h1>
        <div style="color: var(--muted); font-size: 13px; margin-top: 4px;">
          Cryptographic Proof Of Data (POD) Attestation Engine &amp; Zero-DB-Call AI Gateway Prevalidator
        </div>
      </div>
    </div>
    <div class="links" style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
      <span id="activeLlmBadge" class="badge badge-Internal" style="font-size: 11.5px; text-transform: none; padding: 5px 10px;">
        LLM: Built-in Gateway (:4000)
      </span>
      <span id="headerLatencyPill" class="badge badge-Public" style="font-size: 11.5px; text-transform: none; padding: 5px 10px; font-family: ui-monospace, monospace;">
        &#9201; Gate Latency: -- ms
      </span>
      <a href="/dlp" class="btn" style="background: #7c3aed; color: #ffffff; text-decoration: none; margin-left: 0;">&#9729; DLP Connectors (Purview / Cloud)</a>
      <button class="btn" style="background: #0d9488; color: #ffffff;" onclick="toggleEnterpriseScannerDrawer()">&#128640; Enterprise Continuous Scanner</button>
      <button class="btn" style="background: #0284c7;" onclick="toggleEnterpriseStoresDrawer()">&#128452; Enterprise Data Stores (S3 / Lakes / Warehouses)</button>
      <button class="btn" style="background: #2563eb;" onclick="toggleLlmConfig()">&#9881; LLM Provider Config</button>
      <button id="toggleModeBtn" class="btn" style="background: #059669; color: #ffffff;" onclick="toggleMode()">&#128737; Mode: ENFORCE (Click &rarr; Observe)</button>
      <a href="/docs" target="_blank">Prevalidator API</a>
      <a href="http://localhost:18083/docs" target="_blank">Engine API (:18083)</a>
      <a href="http://localhost:18080/docs" target="_blank">Registry API (:18080)</a>
      <a href="http://localhost:18081/docs" target="_blank">Snapshot API (:18081)</a>
    </div>
  </header>

  <!-- ENTERPRISE CONTINUOUS DELTA SCANNER CONFIGURATION DRAWER -->
  <div id="enterpriseScannerDrawer" class="card" style="display: none; border: 2px solid #0d9488; background: #0f172a;">
    <h2>
      <span>&#128640; Enterprise Continuous Background Delta Crawler — Configure What Is Scanned &amp; Rolling Micro-Snapshot Policy</span>
      <button class="btn btn-dark" style="padding: 4px 10px; font-size: 12px;" onclick="toggleEnterpriseScannerDrawer()">&#10005; Close Menu</button>
    </h2>
    <div style="display: grid; grid-template-columns: 1.45fr 1fr; gap: 18px;">
      <!-- LEFT: CONFIGURE TARGET DRIVES, FOLDERS, S3 BUCKETS & WAREHOUSES -->
      <div style="background: #090d16; border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
        <div style="font-size: 13px; font-weight: 700; color: #2dd4bf; margin-bottom: 8px;">
          1. Configure Continuous Scan Targets (Drives, Folders, S3 Buckets, Data Lakes &amp; Warehouses)
        </div>
        <div style="font-size: 11.5px; color: var(--muted); margin-bottom: 10px;">
          Check which estates are included in the zero-limit background delta loop, or click <strong>Sweep Only This</strong> to focus the scanner head on a single drive or cloud store:
        </div>
        <div id="crawlerTargetCheckboxes" style="max-height: 220px; overflow-y: auto; border: 1px solid #1e293b; border-radius: 6px; padding: 8px; margin-bottom: 10px;"></div>
        <div style="display: flex; gap: 8px; align-items: center;">
          <input type="text" id="newCrawlerTargetUri" placeholder="Add drive, folder, or URI (e.g. C:\Users\chuck\Documents or s3://bucket/prefix)" style="margin-bottom: 0; flex: 1;" />
          <button class="btn btn-green" style="white-space: nowrap;" onclick="addCrawlerTarget()">+ Add Scan Target</button>
        </div>
      </div>

      <!-- RIGHT: PASS 1 / PASS 2 DELTA FILTER & ROLLING MICRO-SNAPSHOT SETTINGS -->
      <div style="background: #090d16; border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
        <div style="font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 8px;">
          2. Two-Pass Delta Engine &amp; Rolling Micro-Snapshot Settings
        </div>
        <div style="font-size: 11.5px; color: var(--muted); margin-bottom: 10px; line-height: 1.45;">
          &bull; <strong>Pass 1 (mtime / size / ETag Watermark):</strong> Skips unchanged files in microseconds with 0 disk bytes read.<br/>
          &bull; <strong>Pass 2 (Deep Hash + Presidio + Chunk Digests):</strong> Runs only on new or modified files.<br/>
          &bull; <strong>Rolling Micro-Snapshots:</strong> Flushes &amp; signs a new DSSE Snapshot every <em>N</em> deltas while scanning.
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Micro-Snapshot Flush Threshold</label>
            <select id="crawlerMicroBatchSelect" onchange="saveCrawlerPolicySettings()" style="margin-bottom: 0;">
              <option value="5">Flush Snapshot Every 5 Deltas</option>
              <option value="15" selected>Flush Snapshot Every 15 Deltas</option>
              <option value="50">Flush Snapshot Every 50 Deltas</option>
              <option value="100">Flush Snapshot Every 100 Deltas</option>
            </select>
          </div>
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Scanner Head Pacing</label>
            <select id="crawlerThrottleSelect" onchange="saveCrawlerPolicySettings()" style="margin-bottom: 0;">
              <option value="0">Max Speed (0 ms delay — Full I/O Rate)</option>
              <option value="3.5" selected>Fast Live Ticker (~250+ files/sec)</option>
              <option value="15">Readable Ticker (~60 files/sec)</option>
            </select>
          </div>
        </div>
        <div style="display: flex; gap: 16px; align-items: center; margin-bottom: 12px; font-size: 12.5px;">
          <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="crawlerIncludeCodeChk" checked onchange="saveCrawlerPolicySettings()" />
            Include Code &amp; Hidden Folders
          </label>
          <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="crawlerAutoRevokeChk" checked onchange="saveCrawlerPolicySettings()" />
            Auto-Revoke Deleted Files
          </label>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-green" onclick="controlContinuousCrawler({ running: true })">&#9654; Start Enterprise Scan</button>
          <button class="btn" style="background: #dc2626;" onclick="stopContinuousCrawler()">&#9209; Stop Enterprise Scan</button>
          <button class="btn btn-dark" onclick="saveCrawlerTargetsSelection()">&#10004; Save Target Selection</button>
          <button class="btn btn-amber" onclick="resetCrawlerWatermarks()">&#128260; Clear Watermarks (Force Full Deep Re-Scan)</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ENTERPRISE DATA STORES & REAL-TIME STORAGE EVENT WEBHOOK DRAWER -->
  <div id="enterpriseStoresDrawer" class="card" style="display: none; border: 2px solid #0284c7; background: #0f172a;">
    <h2>
      <span>&#128452; Enterprise Data Store Connectors (AWS S3, Azure ADLS Gen2 / Blob, GCP GCS, Snowflake, BigQuery, PostgreSQL) &amp; Event Webhooks</span>
      <button class="btn btn-dark" style="padding: 4px 10px; font-size: 12px;" onclick="toggleEnterpriseStoresDrawer()">&#10005; Close Menu</button>
    </h2>
    <div style="display: grid; grid-template-columns: 1.25fr 1fr; gap: 18px; margin-bottom: 12px;">
      <!-- LEFT: REGISTER OR SELECT AN ENTERPRISE DATA STORE -->
      <div style="background: #090d16; border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
        <div style="font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 10px;">
          1. Register New Enterprise Data Store or Select Pre-Configured Estate
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1.6fr; gap: 10px; margin-bottom: 8px;">
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Cloud / Warehouse Provider</label>
            <select id="dsProviderSelect" onchange="applyDsTemplate()" style="margin-bottom: 0;">
              <option value="AWS S3">AWS S3 / S3-Compatible Data Lake (s3://)</option>
              <option value="Azure ADLS Gen2 / Blob">Azure ADLS Gen2 / Blob Storage (azblob://)</option>
              <option value="GCP Cloud Storage">Google Cloud Storage Lake (gs://)</option>
              <option value="Snowflake">Snowflake Data Warehouse (snowflake://)</option>
              <option value="Google BigQuery">Google BigQuery Dataset (bigquery://)</option>
              <option value="Databricks Unity Catalog">Databricks Unity Catalog (databricks://)</option>
              <option value="PostgreSQL">PostgreSQL / Operational DB (postgres://)</option>
            </select>
          </div>
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Store URI (Bucket/Prefix or Warehouse Dataset/Schema)</label>
            <input type="text" id="dsUriInput" value="s3://acme-corp-datalake-prod/rag-knowledge" style="margin-bottom: 0;" />
          </div>
        </div>
        <div style="display: grid; grid-template-columns: 1.2fr 1fr 1fr; gap: 10px; margin-bottom: 10px;">
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Display Name</label>
            <input type="text" id="dsNameInput" value="Acme Corp S3 RAG Knowledge Lake" style="margin-bottom: 0;" />
          </div>
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Auth Mode (Zero-Secret First)</label>
            <select id="dsAuthSelect" style="margin-bottom: 0;">
              <option value="iam_role">AWS IAM Role / IRSA</option>
              <option value="managed_identity">Azure Managed Identity</option>
              <option value="workload_identity">GCP Workload Identity / ADC</option>
              <option value="key_pair">Snowflake Key-Pair Auth</option>
              <option value="access_key">Scoped Read-Only Access Key</option>
              <option value="connection_string">Database Connection URI</option>
            </select>
          </div>
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Region / Endpoint</label>
            <input type="text" id="dsRegionInput" value="us-east-1" style="margin-bottom: 0;" />
          </div>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
          <button class="btn btn-green" onclick="registerAndSelectStore()">+ Register &amp; Scan Enterprise Store</button>
          <span id="dsStatusMsg" style="font-size: 12px; color: #34d399;">ETag Fast-Path &amp; Bounded Parquet/Table Sampling Enabled</span>
        </div>
      </div>

      <!-- RIGHT: REAL-TIME CLOUD STORAGE EVENT WEBHOOK (S3 EventBridge / Azure Event Grid / GCS PubSub) -->
      <div style="background: #090d16; border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
        <div style="font-size: 13px; font-weight: 700; color: #fbbf24; margin-bottom: 8px;">
          2. Real-Time Storage Event Webhook (<code>POST /v1/events/storage</code>)
        </div>
        <div style="font-size: 11.5px; color: var(--muted); margin-bottom: 10px;">
          Instead of rescanning petabytes, S3 EventBridge, Azure Event Grid, and GCS Pub/Sub push object change notifications here to auto-attest new uploads or auto-revoke deleted objects in real time.
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Event Type</label>
            <select id="evtTypeSelect" style="margin-bottom: 0;">
              <option value="ObjectCreated:Put">AWS S3 — ObjectCreated:Put (Auto-Attest)</option>
              <option value="Microsoft.Storage.BlobCreated">Azure Event Grid — BlobCreated (Auto-Attest)</option>
              <option value="google.cloud.storage.object.v1.finalized">GCS Pub/Sub — object.finalized (Auto-Attest)</option>
              <option value="ObjectRemoved:Delete">AWS S3 — ObjectRemoved:Delete (Auto-Revoke)</option>
            </select>
          </div>
          <div>
            <label style="font-size: 11.5px; color: var(--muted);">Object Key / Table Name</label>
            <input type="text" id="evtKeyInput" value="live_ingest/q4_board_forecast.parquet" style="margin-bottom: 0;" />
          </div>
        </div>
        <div style="margin-bottom: 8px;">
          <label style="font-size: 11.5px; color: var(--muted);">Sample Payload Content (Presidio Classified on Ingest)</label>
          <input type="text" id="evtSampleInput" value="vp_finance: clark.kent@contoso.com | phone: 212-555-0199 | salary: $210,000" style="margin-bottom: 0;" />
        </div>
        <div style="display: flex; gap: 8px; align-items: center;">
          <button class="btn" style="background: #d97706; color: #fff;" onclick="sendStorageWebhookEvent()">&#9889; Fire Storage Webhook Event Now</button>
          <span id="evtWebhookStatus" style="font-size: 12px; color: #93c5fd;">Ready</span>
        </div>
      </div>
    </div>

    <!-- QUICK-SELECT REGISTERED ENTERPRISE STORES PILLS -->
    <div style="font-size: 12px; color: var(--muted); margin-bottom: 6px;">
      <strong>Registered Enterprise Data Stores (Click any store to point Engine &amp; Prevalidator at it):</strong>
    </div>
    <div id="registeredStoresPills" style="display: flex; gap: 8px; flex-wrap: wrap;"></div>
  </div>

  <!-- CONFIGURATION MENU DRAWER: POINT AT ANY LLM PROVIDER -->
  <div id="llmConfigDrawer" class="card" style="display: none; border: 2px solid #3b82f6; background: #0f172a;">
    <h2>
      <span>&#9881; LLM Provider Configuration — Point G1 Docket Prevalidator at Any Local or Cloud LLM</span>
      <button class="btn btn-dark" style="padding: 4px 10px; font-size: 12px;" onclick="toggleLlmConfig()">&#10005; Close Menu</button>
    </h2>
    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 10px;">
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>1. Select LLM Provider Preset</strong>
        </label>
        <select id="llmPresetSelect" onchange="applyLlmPreset()" style="margin-bottom: 0;">
          <option value="builtin">Built-in G1 Mock Gateway (http://litellm-gateway:4000)</option>
          <option value="lmstudio">LM Studio on Host PC (http://host.docker.internal:1234)</option>
          <option value="ollama">Ollama on Host PC (http://host.docker.internal:11434)</option>
          <option value="litellm_host">LiteLLM / vLLM on Host PC (http://host.docker.internal:4000)</option>
          <option value="openai">OpenAI Official Cloud API (https://api.openai.com)</option>
          <option value="anthropic">Anthropic Official Cloud API (https://api.anthropic.com)</option>
          <option value="gemini">Google Gemini OpenAI API (https://generativelanguage.googleapis.com/v1beta/openai)</option>
          <option value="custom">Custom OpenAI / Anthropic Compatible Endpoint</option>
        </select>
      </div>
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>2. Provider Label &amp; Protocol</strong>
        </label>
        <div style="display: grid; grid-template-columns: 1.3fr 1fr; gap: 8px;">
          <input type="text" id="llmProviderName" value="Built-in G1 Gateway" style="margin-bottom: 0;" placeholder="Provider Name" />
          <select id="llmProtocol" style="margin-bottom: 0;">
            <option value="openai">OpenAI (/v1/chat/completions)</option>
            <option value="anthropic">Anthropic (/v1/messages)</option>
          </select>
        </div>
      </div>
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>3. Upstream LLM Base URL</strong>
        </label>
        <input type="text" id="llmBaseUrl" value="http://litellm-gateway:4000" style="margin-bottom: 0;" placeholder="http://host.docker.internal:1234" />
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; align-items: end; margin-bottom: 12px;">
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>4. Default Model ID</strong> (or select discovered model)
        </label>
        <input type="text" id="llmDefaultModel" value="local-model" style="margin-bottom: 0;" placeholder="e.g. llama3.2, qwen2.5, gpt-4o" />
      </div>
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>5. Provider Egress Classification</strong> (Enforced by Prevalidator)
        </label>
        <select id="llmEgressClass" style="margin-bottom: 0;">
          <option value="local_only">local_only — Local Host / Air-Gapped Model</option>
          <option value="private_cloud">private_cloud — Private VPC / Enterprise Tenant</option>
          <option value="public_api">public_api — External Public Cloud LLM API</option>
        </select>
      </div>
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>6. Upstream API Key</strong> (Optional for Local LLMs)
        </label>
        <input type="password" id="llmApiKey" value="" placeholder="Leave blank for local, or sk-... / anthropic key" style="width: 100%; background: var(--panel2); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-size: 13px; margin-bottom: 0; font-family: ui-monospace, monospace;" />
      </div>
    </div>

    <div style="display: flex; gap: 12px; align-items: center; padding-top: 10px; border-top: 1px solid var(--border);">
      <button class="btn btn-green" onclick="saveLlmConfig()">&#10004; Save &amp; Activate LLM Provider</button>
      <button class="btn" onclick="testLlmConfig()">&#9889; Test Connection &amp; Discover Models</button>
      <div id="llmConfigStatus" style="font-size: 13px; color: #34d399; margin-left: 8px;">
        Active Provider: Built-in G1 Gateway (http://litellm-gateway:4000)
      </div>
    </div>
  </div>

  <!-- REAL-TIME PREVALIDATOR ZERO-DB LATENCY CLOCK & TELEMETRY -->
  <div class="card" style="border-color: #10b981; background: linear-gradient(180deg, #0f172a 0%, #111827 100%); margin-bottom: 18px;">
    <h2 style="border-bottom-color: #1e293b;">
      <span style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 18px;">&#9201;</span>
        <span>Prevalidator Zero-DB Latency Clock (Sub-Millisecond In-Memory Cryptographic Gate)</span>
        <span id="latSlaBadge" class="badge badge-Public">SLA &le; 5.0 ms: 100% PASS</span>
      </span>
      <div style="display: flex; align-items: center; gap: 10px;">
        <button id="benchBtn" class="btn btn-green" style="padding: 6px 12px; font-size: 12px;" onclick="runLatencyBenchmark()">&#9889; Benchmark 100 Live Evaluations</button>
      </div>
    </h2>

    <div style="display: grid; grid-template-columns: 1.35fr repeat(5, 1fr); gap: 12px; align-items: stretch; margin-top: 10px;">
      <!-- DIGITAL CLOCK READOUT -->
      <div style="background: #050811; border: 1px solid #10b981; border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; justify-content: center; box-shadow: inset 0 0 18px rgba(16,185,129,0.12);">
        <div style="font-size: 10.5px; color: #6ee7b7; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 700;">Live Gate Decision Clock</div>
        <div id="latClockDigital" style="font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 26px; font-weight: 800; color: #34d399; margin-top: 4px; letter-spacing: 0.5px;">0.000 ms</div>
        <div id="latClockMicro" style="font-family: ui-monospace, monospace; font-size: 11.5px; color: #94a3b8; margin-top: 2px;">0.0 &mu;s &bull; 0 DB Calls</div>
      </div>

      <div class="score-box" style="margin: 0; display: flex; flex-direction: column; justify-content: center;">
        <div class="lbl">P50 (Median)</div>
        <div id="latP50" class="num" style="font-size: 21px; color: #38bdf8; font-family: ui-monospace, monospace;">-</div>
        <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">Avg: <span id="latAvg">-</span></div>
      </div>

      <div class="score-box" style="margin: 0; display: flex; flex-direction: column; justify-content: center;">
        <div class="lbl">P95 / P99 Tail</div>
        <div id="latP95" class="num" style="font-size: 21px; color: #a78bfa; font-family: ui-monospace, monospace;">-</div>
        <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">P99: <span id="latP99">-</span></div>
      </div>

      <div class="score-box" style="margin: 0; display: flex; flex-direction: column; justify-content: center;">
        <div class="lbl">Dir Batch Enforcer</div>
        <div id="latDirEnforcer" class="num" style="font-size: 21px; color: #34d399; font-family: ui-monospace, monospace;">-</div>
        <div id="latDirPerFile" style="font-size: 11px; color: var(--muted); margin-top: 2px;">- &mu;s / file</div>
      </div>

      <div class="score-box" style="margin: 0; display: flex; flex-direction: column; justify-content: center;">
        <div class="lbl">Batch Throughput</div>
        <div id="latThroughput" class="num" style="font-size: 21px; color: #fbbf24; font-family: ui-monospace, monospace;">-</div>
        <div id="latDirWall" style="font-size: 11px; color: var(--muted); margin-top: 2px;">Disk+Hash: - ms</div>
      </div>

      <div class="score-box" style="margin: 0; display: flex; flex-direction: column; justify-content: center;">
        <div class="lbl">Total Gate Checks</div>
        <div id="latTotalChecks" class="num" style="font-size: 21px; color: #f8fafc; font-family: ui-monospace, monospace;">0</div>
        <div style="font-size: 11px; color: #34d399; margin-top: 2px;">In-Memory Snapshot</div>
      </div>
    </div>

    <!-- SPARKLINE BAR CHART OF RECENT GATE DECISIONS -->
    <div style="margin-top: 12px; background: #090d16; border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; display: flex; align-items: center; gap: 14px;">
      <div style="font-size: 11px; color: var(--muted); white-space: nowrap;">
        <strong>Recent Gate Decisions (ms):</strong><br/>
        <span style="font-size: 10px; color: #64748b;">Green &lt; 1.0 ms &bull; SLA Budget = 5.0 ms</span>
      </div>
      <div id="latSparkline" style="flex: 1; display: flex; align-items: flex-end; gap: 4px; height: 34px; padding-top: 4px;"></div>
    </div>
  </div>

  <!-- LIVE CONTINUOUS ENTERPRISE DELTA SCANNER TELEMETRY BAR ("WHAT IS BEING SCANNED FLASHING BY") -->
  <div class="card" style="border-color: #0d9488; background: linear-gradient(180deg, #091520 0%, #0f172a 100%); margin-bottom: 18px;">
    <h2 style="border-bottom-color: #1e293b;">
      <span style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 18px;">&#128640;</span>
        <span>Enterprise Continuous Background Delta Crawler (Zero File Limits &bull; 2-Pass mtime/ETag Filter &bull; Rolling Micro-Snapshots)</span>
        <span id="crawlerStateBadge" class="badge badge-Public">SWEEPING LIVE</span>
      </span>
      <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
        <button id="crawlerToggleBtn" class="btn btn-green" style="padding: 6px 12px; font-size: 12px;" onclick="toggleContinuousCrawlerRun()">&#9654; Start Enterprise Scan</button>
        <button id="crawlerStopBtn" class="btn" style="background: #dc2626; padding: 6px 12px; font-size: 12px;" onclick="stopContinuousCrawler()">&#9209; Stop Enterprise Scan</button>
        <button class="btn" style="background: #0d9488; padding: 6px 12px; font-size: 12px;" onclick="sweepSelectedTargetUnbounded()">&#127919; Sweep Selected Drive/Store Unbounded</button>
        <button class="btn btn-dark" style="padding: 6px 12px; font-size: 12px;" onclick="resetCrawlerWatermarks()">&#128260; Force Deep Re-Scan</button>
        <button class="btn btn-dark" style="padding: 6px 12px; font-size: 12px;" onclick="toggleEnterpriseScannerDrawer()">&#9881; Configure What Is Scanned</button>
      </div>
    </h2>

    <!-- ROLLING COUNTERS -->
    <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 10px 0;">
      <div class="score-box" style="margin: 0; padding: 10px;">
        <div class="lbl">Files Swept (Zero Cap)</div>
        <div id="crFilesSwept" class="num" style="font-size: 22px; color: #f8fafc; font-family: ui-monospace, monospace;">0</div>
        <div id="crPassNum" style="font-size: 11px; color: var(--muted);">Pass #1 &bull; Watermarks: 0</div>
      </div>
      <div class="score-box" style="margin: 0; padding: 10px;">
        <div class="lbl">Unchanged (Delta Skipped)</div>
        <div id="crSkipped" class="num" style="font-size: 22px; color: #38bdf8; font-family: ui-monospace, monospace;">0</div>
        <div style="font-size: 11px; color: var(--muted);">Pass 1: mtime / size / ETag match</div>
      </div>
      <div class="score-box" style="margin: 0; padding: 10px;">
        <div class="lbl">New / Modified Attested</div>
        <div id="crDeltas" class="num" style="font-size: 22px; color: #34d399; font-family: ui-monospace, monospace;">0</div>
        <div id="crRevoked" style="font-size: 11px; color: var(--muted);">Pass 2 Deep Scan &bull; Revoked: 0</div>
      </div>
      <div class="score-box" style="margin: 0; padding: 10px;">
        <div class="lbl">Live Scan Rate</div>
        <div id="crRate" class="num" style="font-size: 22px; color: #fbbf24; font-family: ui-monospace, monospace;">0 /s</div>
        <div id="crTargetNow" style="font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">Target: -</div>
      </div>
      <div class="score-box" style="margin: 0; padding: 10px;">
        <div class="lbl">Rolling Micro-Snapshots</div>
        <div id="crSnapshots" class="num" style="font-size: 22px; color: #a78bfa; font-family: ui-monospace, monospace;">0</div>
        <div id="crPendingDeltas" style="font-size: 11px; color: var(--muted);">Pending flush: 0 deltas</div>
      </div>
    </div>

    <!-- REAL-TIME FLASHING FILE TICKER ("WHAT IS BEING SCANNED FLASHING BY") -->
    <div style="background: #04070e; border: 1px solid #0d9488; border-radius: 8px; padding: 10px 14px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;">
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 6px; margin-bottom: 6px;">
        <div style="font-size: 12px; color: #2dd4bf; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          &#9889; ACTIVE SCANNER HEAD: <span id="crCurrentHeadFile" style="color: #f8fafc;">Initializing continuous delta crawler...</span>
        </div>
        <span style="font-size: 10.5px; color: #64748b; white-space: nowrap; margin-left: 10px;">Live Stream (Pass 1 Skip vs Pass 2 Delta)</span>
      </div>
      <div id="crTickerStream" style="height: 112px; overflow-y: auto; font-size: 11.5px; line-height: 1.55; color: #cbd5e1;"></div>
    </div>
  </div>

  <!-- TOP WORKFLOW: ENTERPRISE DATA STORE OR PC DIRECTORY SELECTION + ATTESTATION + PREVALIDATOR SCAN -->
  <div class="card" style="border-color: #3b82f6;">
    <h2>
      <span>Point System at Any Enterprise Data Store (<code>s3://</code>, <code>azblob://</code>, <code>gs://</code>, <code>snowflake://</code>, <code>bigquery://</code>, <code>postgres://</code>) or PC Directory</span>
      <span id="folderSourceBadge" class="badge badge-Internal">Direct PC Disk Path</span>
    </h2>

    <div style="display: grid; grid-template-columns: 1.45fr 0.95fr auto; gap: 14px; align-items: end; margin-bottom: 12px;">
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>Select Enterprise Data Store (S3, Azure ADLS, GCS, Snowflake, BigQuery, Postgres) or Local PC Drive/Folder:</strong>
        </label>
        <select id="pcFolderSelect" style="margin-bottom: 0; font-size: 14px; font-weight: 600;" onchange="selectPresetFolder()">
          <option value="C:\Users\chuck\pc_demo_folder">📁 C:\Users\chuck\pc_demo_folder — Sample Disparate Files</option>
          <option value="s3://contoso-ai-datalake-prod/rag-corpus">☁️ [AWS S3] s3://contoso-ai-datalake-prod/rag-corpus — Production AI &amp; RAG Data Lake</option>
          <option value="azblob://contosodatalake.blob.core.windows.net/enterprise-knowledge">☁️ [Azure ADLS Gen2 / Blob] azblob://contosodatalake.blob.core.windows.net/enterprise-knowledge</option>
          <option value="gs://contoso-vertex-lake-us/curated-zones">☁️ [GCP Cloud Storage] gs://contoso-vertex-lake-us/curated-zones — Vertex AI Data Lake</option>
          <option value="snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC">☁️ [Snowflake] snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC</option>
          <option value="bigquery://contoso-gcp-analytics/enterprise_mart">☁️ [Google BigQuery] bigquery://contoso-gcp-analytics/enterprise_mart</option>
          <option value="postgres://estate-db:5432/estate">☁️ [PostgreSQL] postgres://estate-db:5432/estate — Operational DB (Live SQL)</option>
          <option value="C:\">🖴 C:\ — Entire C: Drive (Recursive Data Scan)</option>
          <option value="D:\">🖴 D:\ — Entire D: Drive (Recursive Data Scan)</option>
        </select>
        <input type="hidden" id="pcPathInput" value="C:\Users\chuck\pc_demo_folder" />
      </div>

      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>Drill Into Subdirectory / Or Enter Custom Store URI</strong> (<code>s3://...</code>, <code>gs://...</code>, <code>D:\...</code>):
        </label>
        <div style="display: flex; gap: 6px;">
          <select id="subDirSelect" style="margin-bottom: 0; font-size: 13px;" onchange="selectSubdirectory()">
            <option value="">-- Current Selected Store / Directory --</option>
          </select>
        </div>
      </div>

      <div style="display: flex; gap: 8px;">
        <button class="btn" style="background: #0284c7; white-space: nowrap;" onclick="toggleEnterpriseStoresDrawer()">&#128452; + Connect Cloud Store / S3</button>
        <input type="file" id="winFolderPicker" webkitdirectory directory multiple style="display: none;" onchange="onWinFolderPicked(event)" />
        <button class="btn" style="white-space: nowrap;" onclick="document.getElementById('winFolderPicker').click()">📂 Or Pick PC Folder</button>
      </div>
    </div>

    <!-- INTERACTIVE PC DRIVE & FOLDER NAVIGATOR -->
    <div id="pcBrowserBox" class="folder-browser">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <div>
          <strong>Browsing PC Path:</strong> <code id="browserCurrentPath" style="font-size: 13px; color: #34d399;">D:\attestation</code>
          <span id="browserFileCount" class="badge badge-Public" style="margin-left: 8px;">0 files in this folder</span>
        </div>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-dark" style="padding: 5px 10px; font-size: 12px;" onclick="browseTo('D:\\\\')">D:\ Drive</button>
          <button class="btn btn-dark" style="padding: 5px 10px; font-size: 12px;" onclick="browseTo('C:\\\\Users\\\\chuck')">C:\Users\chuck</button>
          <button class="btn btn-dark" style="padding: 5px 10px; font-size: 12px;" onclick="browseUp()">⬆ Up One Level</button>
          <button class="btn btn-green" style="padding: 5px 12px; font-size: 12px;" onclick="useBrowsedFolder()">✔ Select This Folder &amp; Run Attestation</button>
          <button class="btn btn-dark" style="padding: 5px 10px; font-size: 12px;" onclick="togglePcBrowser()">Close</button>
        </div>
      </div>
      <div id="browserSampleFiles" style="font-size: 12px; color: var(--muted); margin-bottom: 8px;"></div>
      <div id="browserSubdirs"></div>
    </div>

    <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap; padding-top: 10px; border-top: 1px solid var(--border);">
      <button id="runAttestBtn" class="btn btn-green" onclick="attestSelectedDirectory()">1. Run Attestation on Directory (Engine)</button>
      <div style="display: flex; align-items: center; gap: 6px; background: #090d16; border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px;">
        <span style="font-size: 11.5px; color: var(--muted);">Demo File Cap:</span>
        <select id="demoMaxFilesSelect" style="width: 155px; margin-bottom: 0; padding: 4px 6px; font-size: 12px;">
          <option value="120" selected>120 Files (Fast Demo)</option>
          <option value="500">500 Files (Medium)</option>
          <option value="2500">2,500 Files (Deep)</option>
          <option value="0">Unbounded (All Files)</option>
        </select>
        <label style="font-size: 11.5px; color: var(--muted); display: flex; align-items: center; gap: 4px; cursor: pointer; white-space: nowrap;">
          <input type="checkbox" id="demoIncludeCodeChk" /> +Code Dirs
        </label>
      </div>
      <button class="btn" style="background: #0d9488;" onclick="sweepSelectedTargetUnbounded()">&#128640; Enterprise Continuous Sweep This Target</button>
      <button class="btn btn-amber" onclick="dropUnattestedFile()">+ Add Unattested File</button>
      <div style="margin-left: auto; display: flex; gap: 8px; align-items: center;">
        <span style="font-size: 12px; color: var(--muted);">Caller Clearance:</span>
        <select id="dirCallerKey" style="width: 185px; margin-bottom: 0;">
          <option value="pod-key-confidential" selected>Confidential Clearance</option>
          <option value="pod-key-public">Public Clearance</option>
          <option value="pod-key-internal">Internal Clearance</option>
          <option value="pod-key-restricted">Restricted Clearance</option>
        </select>
        <span style="font-size: 12px; color: var(--muted);">Target Egress:</span>
        <select id="dirModelSelect" style="width: 170px; margin-bottom: 0;">
          <option value="local-model" selected>local-model (local_only)</option>
          <option value="vpc-model">vpc-model (private_cloud)</option>
          <option value="gpt-4o">gpt-4o (public_api)</option>
        </select>
        <button id="runPrevalBtn" class="btn" onclick="prevalidateSelectedDirectory()">2. Run Prevalidator Scan on Directory</button>
      </div>
    </div>
  </div>

  <!-- SIDE-BY-SIDE RESULTS: ENGINE ATTESTATION REPORT vs PREVALIDATOR DIRECTORY SCANNER -->
  <div class="grid-2">
    <!-- LEFT: ENGINE DIRECTORY ATTESTATION RESULTS -->
    <div class="card">
      <h2>
        <span>Step 1 — Attestation Engine Directory Report</span>
        <span id="attestStatusText" style="font-size: 12px; color: var(--muted);">Ready</span>
      </h2>

      <!-- VERIFIABLE PLAIN-ENGLISH FILE COUNT BANNER (ENGINE) -->
      <div id="attestEnglishBanner" class="english-verdict">
        Loading verifiable file count from Attestation Engine...
      </div>

      <div class="score-grid" style="grid-template-columns: repeat(3, 1fr);">
        <div class="score-box">
          <div class="lbl">Files Discovered</div>
          <div id="attTotal" class="num">-</div>
        </div>
        <div class="score-box">
          <div class="lbl">Signed Active Records</div>
          <div id="attActive" class="num" style="color: #34d399;">-</div>
        </div>
        <div class="score-box">
          <div class="lbl">Held in Review Queue</div>
          <div id="attHeld" class="num" style="color: #fbbf24;">-</div>
        </div>
      </div>
      <table id="attestedFilesTable">
        <thead>
          <tr>
            <th>File Name (Click to Inspect)</th>
            <th>Owner</th>
            <th>Type</th>
            <th>Classified Tier</th>
            <th>AI Policy</th>
            <th>Content SHA-256</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <!-- RIGHT: PREVALIDATOR DIRECTORY BATCH SCANNER RESULTS -->
    <div class="card">
      <h2>
        <span>Step 2 — Prevalidator Directory Verification Scorecard</span>
        <span id="prevalStatusText" style="font-size: 12px; color: var(--muted);">Ready</span>
      </h2>

      <!-- VERIFIABLE PLAIN-ENGLISH FILE COUNT BANNER (PREVALIDATOR) -->
      <div id="prevalEnglishBanner" class="english-verdict">
        Loading verifiable Prevalidator pass/fail file count...
      </div>

      <div class="score-grid">
        <div class="score-box">
          <div class="lbl">Total Files in Dir</div>
          <div id="pvTotal" class="num">-</div>
        </div>
        <div class="score-box">
          <div class="lbl">Files Passed</div>
          <div id="pvPassed" class="num" style="color: #34d399;">-</div>
        </div>
        <div class="score-box">
          <div class="lbl">Files Did Not Pass</div>
          <div id="pvFailed" class="num" style="color: #f87171;">-</div>
        </div>
        <div class="score-box">
          <div class="lbl">Unattested Files</div>
          <div id="pvUnattested" class="num" style="color: #ef4444;">-</div>
        </div>
      </div>
      <table id="prevalidatedFilesTable">
        <thead>
          <tr>
            <th>File Name (Click to Inspect)</th>
            <th>Attestation State</th>
            <th>Tier</th>
            <th>Prevalidator Verdict</th>
            <th>Reason / Detail</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- BOTTOM SECTION: SNAPSHOT TABLE + SINGLE PROMPT PLAYGROUND -->
  <div class="grid-2">
    <div>
      <div class="card">
        <h2>Active Signed Snapshot Entries (In-Memory Contract)</h2>
        <div id="snapMeta" style="font-size: 12px; color: var(--muted); margin-bottom: 10px;">Loading snapshot...</div>
        <table id="entriesTable">
          <thead>
            <tr>
              <th>Locator (Click to Inspect)</th>
              <th>Tier</th>
              <th>Clearance</th>
              <th>Egress</th>
              <th>AI Rule</th>
              <th>SHA-256</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="card">
        <h2>Operator Audit Log (Internal Reason Codes)</h2>
        <table id="auditTable">
          <thead>
            <tr>
              <th>Time</th>
              <th>Mode</th>
              <th>Decision</th>
              <th>Gate Latency</th>
              <th>Reason Codes</th>
              <th>Clearance / Egress</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>

    <div>
      <div class="card">
        <h2>Single LLM Prompt Playground (OpenAI &amp; Anthropic Proxy)</h2>
        <div style="margin-bottom: 10px;">
          <button class="btn btn-dark" style="margin-right:4px;margin-bottom:4px;" onclick="loadPreset('allow')">1. Allow (Public)</button>
          <button class="btn btn-dark" style="margin-right:4px;margin-bottom:4px;" onclick="loadPreset('strip')">2. Strip (Confidential)</button>
          <button class="btn btn-dark" style="margin-right:4px;margin-bottom:4px;" onclick="loadPreset('restricted')">3. Refuse (Restricted)</button>
          <button class="btn btn-dark" style="margin-right:4px;margin-bottom:4px;" onclick="loadPreset('unattested')">4. Refuse (Unattested)</button>
        </div>

        <label style="font-size: 12px; color: var(--muted);">Protocol Endpoint</label>
        <select id="endpointSelect">
          <option value="/v1/chat/completions">OpenAI — POST /v1/chat/completions</option>
          <option value="/v1/messages">Anthropic — POST /v1/messages</option>
        </select>

        <div class="grid-2" style="gap: 10px;">
          <div>
            <label style="font-size: 12px; color: var(--muted);">Caller Clearance Key</label>
            <select id="callerKey">
              <option value="pod-key-public">pod-key-public (Public)</option>
              <option value="pod-key-internal">pod-key-internal (Internal)</option>
              <option value="pod-key-confidential">pod-key-confidential (Confidential)</option>
              <option value="pod-key-restricted">pod-key-restricted (Restricted)</option>
            </select>
          </div>
          <div>
            <label style="font-size: 12px; color: var(--muted);">Target Gateway Model</label>
            <select id="modelSelect">
              <option value="gpt-4o">gpt-4o (public_api)</option>
              <option value="vpc-model">vpc-model (private_cloud)</option>
              <option value="local-model">local-model (local_only)</option>
            </select>
          </div>
        </div>

        <textarea id="promptInput" rows="4"></textarea>
        <button class="btn" style="width: 100%; justify-content: center;" onclick="sendRequest()">Send Prompt Through Prevalidator</button>

        <h2 style="margin-top: 16px;">Gateway / Prevalidator Response (<span id="statusSpan">-</span>)</h2>
        <pre id="responseBox">Ready.</pre>
      </div>
    </div>
  </div>

  <!-- FILE / OBJECT CLASSIFICATION, OWNERSHIP & ATTESTATION INSPECTOR MODAL DRAWER -->
  <div id="fileInspectorModal" class="inspector-overlay" onclick="if(event.target === this) closeFileInspector()">
    <div class="inspector-modal">
      <div class="inspector-header">
        <div style="flex: 1; min-width: 0;">
          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <span style="font-size: 20px;">&#128269;</span>
            <span id="inspTitle" style="font-size: 18px; font-weight: 800; color: #f8fafc;">Object Attestation Inspector</span>
            <span id="inspTierBadge" class="badge badge-Public">PUBLIC</span>
            <span id="inspStatusBadge" class="badge badge-Internal">ISSUED</span>
            <span id="inspPrevalBadge" class="badge badge-PASS" style="display: none;">PASS</span>
          </div>
          <div style="margin-top: 6px; font-size: 12px; color: #93c5fd; font-family: ui-monospace, monospace; word-break: break-all;">
            Canonical Locator: <strong id="inspLocator">-</strong>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
          <button class="btn btn-green" style="padding: 6px 12px; font-size: 12px;" onclick="loadInspectedFileIntoPlayground()">&#129514; Load in Prompt Playground</button>
          <button class="btn btn-dark" style="padding: 6px 12px; font-size: 12px;" onclick="copyInspectedJson()">&#128203; Copy Signed DSSE JSON</button>
          <button class="btn" style="background: #dc2626; padding: 6px 12px; font-size: 12px;" onclick="closeFileInspector()">&#10005; Close</button>
        </div>
      </div>

      <div class="inspector-body">
        <div id="inspBanner" class="english-verdict" style="margin-bottom: 0; font-size: 13px; padding: 10px 14px;">
          Loading full 32-field POD in-toto v1 Attestation Statement &amp; DSSE signature envelope...
        </div>

        <div class="inspector-grid">
          <!-- GROUP 1 & 2: OWNERSHIP, STEWARDSHIP & ASSET IDENTITY -->
          <div class="inspector-section">
            <h3>
              <span>&#128100; Ownership, Governance &amp; Asset Identity</span>
              <span style="font-size: 10.5px; color: var(--muted);">Groups 1 &amp; 2</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Accountable Owner</div><div id="inspOwner" class="kv-val" style="color: #38bdf8; font-weight: 700;">-</div></div>
            <div class="kv-row"><div class="kv-label">Data Steward</div><div id="inspSteward" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Organizational Unit</div><div id="inspOrgUnit" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Jurisdiction</div><div id="inspJurisdiction" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Attestation Record ID</div><div class="kv-val"><code id="inspRecordId">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Object Type &amp; Env</div><div class="kv-val"><code id="inspObjTypeEnv">-</code></div></div>
          </div>

          <!-- GROUP 5: CLASSIFICATION & DETECTED SENSITIVE ENTITIES -->
          <div class="inspector-section">
            <h3>
              <span>&#128270; Classification &amp; Sensitive Entity Findings</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 5</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Classified Tier</div><div id="inspClassTier" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Confidence Score</div><div id="inspConfidence" class="kv-val" style="font-weight: 700; color: #34d399;">-</div></div>
            <div class="kv-row"><div class="kv-label">Classifier Engine</div><div class="kv-val"><code id="inspClassifierEngine">-</code></div></div>
            <div style="margin-top: 8px;">
              <div class="kv-label" style="margin-bottom: 6px;">Detected Sensitive Entity Categories (PII / PHI / PCI / Labels):</div>
              <div id="inspSensitiveCats" style="background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 8px; max-height: 115px; overflow-y: auto; font-size: 12px;">
                -
              </div>
            </div>
          </div>

          <!-- GROUP 6: AI HANDLING & ZERO-TRUST ENFORCEMENT POLICY -->
          <div class="inspector-section">
            <h3>
              <span>&#128737; AI Handling &amp; Zero-Trust Gate Policy</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 6</span>
            </h3>
            <div class="kv-row"><div class="kv-label">AI Eligibility Rule</div><div id="inspAiRule" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Minimum Clearance</div><div id="inspMinClearance" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Allowed Egress Class</div><div id="inspEgressClass" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Allow RAG Indexing</div><div id="inspAllowRag" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Allow Model Training</div><div id="inspAllowTrain" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Redaction Categories</div><div class="kv-val"><code id="inspRedactCats">-</code></div></div>
          </div>

          <!-- GROUP 4: CRYPTOGRAPHIC INTEGRITY & CHUNK DIGESTS -->
          <div class="inspector-section">
            <h3>
              <span>&#128272; Cryptographic Integrity &amp; RAG Chunk Digests</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 4</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Attested SHA-256</div><div class="kv-val"><code id="inspContentSha" style="color: #34d399;">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Observed Disk SHA-256</div><div class="kv-val"><code id="inspObservedSha">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Extracted Text SHA-256</div><div class="kv-val"><code id="inspTextSha">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Schema SHA-256</div><div class="kv-val"><code id="inspSchemaSha">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Fingerprint Method</div><div class="kv-val"><code id="inspFpMethod">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Size &amp; Row Count</div><div id="inspSizeRows" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Verified Chunk Hashes</div><div id="inspChunkCount" class="kv-val">-</div></div>
          </div>

          <!-- GROUP 3: PROVENANCE, SCANNER & OPENLINEAGE -->
          <div class="inspector-section">
            <h3>
              <span>&#129517; Provenance, Discovery &amp; OpenLineage</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 3</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Attested By Engine</div><div class="kv-val"><code id="inspAttestedBy">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Source System</div><div class="kv-val"><code id="inspSourceSystem">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Scanner Version</div><div class="kv-val"><code id="inspScannerVer">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Discovered At</div><div class="kv-val"><code id="inspDiscoveredAt">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Upstream Lineage</div><div id="inspDerivedFrom" class="kv-val">-</div></div>
          </div>

          <!-- GROUP 7: LIFECYCLE, VALIDITY & DSSE SIGNATURE -->
          <div class="inspector-section">
            <h3>
              <span>&#9201; Lifecycle, Validity &amp; Ed25519 DSSE Signature</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 7</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Lifecycle Status</div><div id="inspLifeStatus" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Issued At (UTC)</div><div class="kv-val"><code id="inspIssuedAt">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Expires At &amp; TTL</div><div class="kv-val"><code id="inspExpiresAt">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Previous Record ID</div><div class="kv-val"><code id="inspPrevRecId">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Active Snapshot Status</div><div id="inspSnapStatus" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">DSSE Signing Key ID</div><div class="kv-val"><code id="inspDsseKeyId" style="color: #a78bfa;">-</code></div></div>
          </div>
        </div>

        <!-- EXPANDABLE CHUNK HASHES & RAW IN-TOTO / DSSE ENVELOPE JSON -->
        <details style="background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px;">
          <summary style="cursor: pointer; font-size: 12.5px; font-weight: 700; color: #93c5fd;">
            &#128196; View Raw In-Toto v1 Attestation Statement, DSSE Signature Envelope &amp; Canonical Chunk Hashes JSON
          </summary>
          <pre id="inspRawJson" style="margin-top: 10px; max-height: 240px; overflow-y: auto; font-size: 11.5px; color: #cbd5e1;">-</pre>
        </details>
      </div>
    </div>
  </div>

  <footer>
    <div class="footer-brand">
      <img src="/assets/g1-logo.png" alt="G1 Logo" class="footer-logo" />
      <span><strong>G1 Docket</strong> by <strong>G1163RT Security Labs</strong></span>
    </div>
    <div>
      Cryptographic Proof Of Data (POD) Framework v0.1 &bull; DSSE Signed Provenance &amp; Zero-DB-Call Enforcement
    </div>
  </footer>

  <script>
    const ADMIN_KEY = "pod-dev-admin-key";
    let currentMode = "enforce";
    let browserPickedFiles = null;
    let currentBrowsedPath = "D:\\\\attestation";
    let parentBrowsedPath = "D:\\\\";

    function isEnterpriseUri(val) {
      if (!val) return false;
      const lower = val.trim().toLowerCase();
      return (
        lower.startsWith('s3://') ||
        lower.startsWith('azblob://') ||
        lower.startsWith('abfss://') ||
        lower.startsWith('gs://') ||
        lower.startsWith('postgres://') ||
        lower.startsWith('postgresql://') ||
        lower.startsWith('snowflake://') ||
        lower.startsWith('bigquery://') ||
        lower.startsWith('databricks://') ||
        lower.startsWith('sharepoint://')
      );
    }

    function updateSourceBadgeForPath(val) {
      const badge = document.getElementById('folderSourceBadge');
      if (!badge) return;
      if (isEnterpriseUri(val)) {
        const scheme = val.split('://')[0].toUpperCase();
        badge.textContent = `Enterprise Cloud Store (${scheme}://)`;
        badge.className = 'badge badge-Public';
      } else {
        badge.textContent = 'Direct PC Disk Path';
        badge.className = 'badge badge-Internal';
      }
    }

    function clearPickedFiles() {
      browserPickedFiles = null;
      updateSourceBadgeForPath(document.getElementById('pcPathInput').value);
    }

    function toggleEnterpriseStoresDrawer() {
      const drawer = document.getElementById('enterpriseStoresDrawer');
      if (!drawer) return;
      if (drawer.style.display === 'none' || !drawer.style.display) {
        drawer.style.display = 'block';
        loadEnterpriseStoresPills();
      } else {
        drawer.style.display = 'none';
      }
    }

    function applyDsTemplate() {
      const prov = document.getElementById('dsProviderSelect').value;
      const uriEl = document.getElementById('dsUriInput');
      const nameEl = document.getElementById('dsNameInput');
      const authEl = document.getElementById('dsAuthSelect');
      const regEl = document.getElementById('dsRegionInput');
      if (prov === 'AWS S3') {
        uriEl.value = 's3://acme-corp-datalake-prod/rag-knowledge';
        nameEl.value = 'Acme Corp S3 RAG Knowledge Lake';
        authEl.value = 'iam_role';
        regEl.value = 'us-east-1';
      } else if (prov === 'Azure ADLS Gen2 / Blob') {
        uriEl.value = 'azblob://acmedatalake.blob.core.windows.net/curated-zone';
        nameEl.value = 'Acme Azure ADLS Gen2 Curated Zone';
        authEl.value = 'managed_identity';
        regEl.value = 'eastus2';
      } else if (prov === 'GCP Cloud Storage') {
        uriEl.value = 'gs://acme-vertex-rag-lake/embeddings';
        nameEl.value = 'Acme GCP Vertex AI Embeddings Lake';
        authEl.value = 'workload_identity';
        regEl.value = 'us-central1';
      } else if (prov === 'Snowflake') {
        uriEl.value = 'snowflake://acme.us-east-1.snowflakecomputing.com/ANALYTICS_PROD/PUBLIC';
        nameEl.value = 'Acme Snowflake ANALYTICS_PROD Warehouse';
        authEl.value = 'key_pair';
        regEl.value = 'us-east-1';
      } else if (prov === 'Google BigQuery') {
        uriEl.value = 'bigquery://acme-gcp-data/customer_360';
        nameEl.value = 'Acme BigQuery customer_360 Dataset';
        authEl.value = 'workload_identity';
        regEl.value = 'US';
      } else if (prov === 'Databricks Unity Catalog') {
        uriEl.value = 'databricks://acme-lakehouse.cloud.databricks.com/main/gold_rag';
        nameEl.value = 'Acme Databricks Unity Catalog (main.gold_rag)';
        authEl.value = 'iam_role';
        regEl.value = 'us-west-2';
      } else if (prov === 'PostgreSQL') {
        uriEl.value = 'postgres://estate-db:5432/estate';
        nameEl.value = 'PostgreSQL Enterprise Operational DB';
        authEl.value = 'connection_string';
        regEl.value = 'local-vpc';
      }
    }

    async function loadEnterpriseStoresPills() {
      try {
        const resp = await fetch('/v1/admin/datastores', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } });
        if (!resp.ok) return;
        const data = await resp.json();
        const container = document.getElementById('registeredStoresPills');
        if (!container) return;
        container.innerHTML = '';
        (data.stores || []).forEach(s => {
          const btn = document.createElement('button');
          btn.className = 'btn btn-dark';
          btn.style.fontSize = '12px';
          btn.style.padding = '6px 11px';
          btn.style.border = '1px solid #0284c7';
          btn.textContent = `☁️ ${s.provider}: ${s.uri}`;
          btn.onclick = async () => {
            await pointAtEnterpriseStore(s.uri, s.label);
          };
          container.appendChild(btn);
        });
      } catch (e) {}
    }

    async function pointAtEnterpriseStore(uri, labelText) {
      const sel = document.getElementById('pcFolderSelect');
      let exists = Array.from(sel.options).some(o => o.value === uri);
      if (!exists) {
        const opt = document.createElement('option');
        opt.value = uri;
        opt.textContent = labelText || `☁️ ${uri}`;
        sel.insertBefore(opt, sel.firstChild);
      }
      sel.value = uri;
      document.getElementById('pcPathInput').value = uri;
      clearPickedFiles();
      const subSel = document.getElementById('subDirSelect');
      subSel.innerHTML = `<option value="">-- Cloud / Warehouse Store: ${uri} --</option>`;
      await attestSelectedDirectory();
    }

    async function registerAndSelectStore() {
      const provider = document.getElementById('dsProviderSelect').value;
      const uri = document.getElementById('dsUriInput').value.trim();
      const name = document.getElementById('dsNameInput').value.trim();
      const auth_mode = document.getElementById('dsAuthSelect').value;
      const region = document.getElementById('dsRegionInput').value.trim();
      const statusEl = document.getElementById('dsStatusMsg');
      statusEl.textContent = 'Registering store...';
      try {
        const resp = await fetch('/v1/admin/datastores', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
          body: JSON.stringify({ provider, uri, name, auth_mode, region })
        });
        const data = await resp.json();
        if (!resp.ok) {
          statusEl.textContent = 'Error: ' + (data.detail || resp.status);
          return;
        }
        statusEl.textContent = `✔ Registered & activated ${data.store.uri}`;
        await loadEnterpriseStoresPills();
        await pointAtEnterpriseStore(data.store.uri, data.store.label);
      } catch (e) {
        statusEl.textContent = 'Error: ' + e;
      }
    }

    async function sendStorageWebhookEvent() {
      const curStore = isEnterpriseUri(document.getElementById('pcPathInput').value)
        ? document.getElementById('pcPathInput').value
        : 's3://contoso-ai-datalake-prod/rag-corpus';
      const event_type = document.getElementById('evtTypeSelect').value;
      const object_key = document.getElementById('evtKeyInput').value.trim();
      const sample_text = document.getElementById('evtSampleInput').value.trim();
      const st = document.getElementById('evtWebhookStatus');
      st.textContent = 'Sending webhook event...';
      try {
        const resp = await fetch('/v1/admin/events/storage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
          body: JSON.stringify({ store_uri: curStore, event_type, object_key, sample_text })
        });
        const data = await resp.json();
        if (!resp.ok) {
          st.textContent = 'Error: ' + (data.detail || resp.status);
          return;
        }
        const ev = data.event;
        st.textContent = `✔ ${ev.action}: ${ev.locator} (Tier: ${ev.tier})`;
        await pointAtEnterpriseStore(curStore);
      } catch (e) {
        st.textContent = 'Error: ' + e;
      }
    }

    async function onWinFolderPicked(event) {
      const fileList = Array.from(event.target.files || []);
      if (!fileList.length) return;
      const folderName = (fileList[0].webkitRelativePath || fileList[0].name).split('/')[0] || 'selected_folder';
      document.getElementById('pcPathInput').value = `[Windows Explorer Folder] ${folderName} (${fileList.length} files)`;
      document.getElementById('folderSourceBadge').textContent = `Windows Explorer Folder (${fileList.length} files)`;
      const payload = [];
      for (const f of fileList) {
        const buf = await f.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        payload.push({
          relative_path: f.webkitRelativePath || f.name,
          content_b64: btoa(binary)
        });
      }
      browserPickedFiles = payload;
      await attestSelectedDirectory();
      await prevalidateSelectedDirectory();
    }

    async function selectPresetFolder() {
      const val = document.getElementById('pcFolderSelect').value;
      document.getElementById('pcPathInput').value = val;
      clearPickedFiles();
      if (isEnterpriseUri(val)) {
        const subSel = document.getElementById('subDirSelect');
        subSel.innerHTML = `<option value="">-- Cloud / Enterprise Store: ${val} --</option>`;
      } else {
        await loadSubdirectoriesIntoSelect(val);
      }
      await attestSelectedDirectory();
    }

    async function selectSubdirectory() {
      const subVal = document.getElementById('subDirSelect').value;
      if (!subVal) return;
      document.getElementById('pcPathInput').value = subVal;
      const mainSel = document.getElementById('pcFolderSelect');
      let exists = Array.from(mainSel.options).some(o => o.value === subVal);
      if (!exists) {
        const opt = document.createElement('option');
        opt.value = subVal;
        opt.textContent = '📁 ' + subVal;
        mainSel.insertBefore(opt, mainSel.firstChild);
      }
      mainSel.value = subVal;
      clearPickedFiles();
      await loadSubdirectoriesIntoSelect(subVal);
      await attestSelectedDirectory();
    }

    async function loadSubdirectoriesIntoSelect(targetPath) {
      try {
        const resp = await fetch('/v1/admin/browse-dir?path=' + encodeURIComponent(targetPath), {
          headers: { 'X-POD-Admin-Key': ADMIN_KEY }
        });
        if (!resp.ok) return;
        const data = await resp.json();
        const subSel = document.getElementById('subDirSelect');
        subSel.innerHTML = '';
        const headOpt = document.createElement('option');
        headOpt.value = '';
        headOpt.textContent = `-- Inside ${data.current_path} (${data.direct_file_count} direct files, ${(data.subdirectories || []).length} subfolders) --`;
        subSel.appendChild(headOpt);

        if (data.parent_path) {
          const upOpt = document.createElement('option');
          upOpt.value = data.parent_path;
          upOpt.textContent = `⬆ Up to Parent (${data.parent_path})`;
          subSel.appendChild(upOpt);
        }

        (data.subdirectories || []).forEach(sub => {
          const opt = document.createElement('option');
          opt.value = sub.path;
          opt.textContent = `📁 ${sub.name} (${sub.path})`;
          subSel.appendChild(opt);
        });
      } catch (e) {}
    }

    function togglePcBrowser() {
      const box = document.getElementById('pcBrowserBox');
      if (box.style.display === 'block') {
        box.style.display = 'none';
      } else {
        box.style.display = 'block';
        browseTo(document.getElementById('pcPathInput').value || 'D:\\\\attestation');
      }
    }

    async function browseTo(targetPath) {
      try {
        const resp = await fetch('/v1/admin/browse-dir?path=' + encodeURIComponent(targetPath), {
          headers: { 'X-POD-Admin-Key': ADMIN_KEY }
        });
        const data = await resp.json();
        if (!resp.ok) {
          alert('Cannot browse path: ' + (data.detail || targetPath));
          return;
        }
        currentBrowsedPath = data.current_path;
        parentBrowsedPath = data.parent_path;
        document.getElementById('browserCurrentPath').textContent = data.current_path;
        document.getElementById('browserFileCount').textContent = `${data.direct_file_count} file(s) directly inside this folder`;
        document.getElementById('browserSampleFiles').textContent = data.sample_files.length
          ? `Files here: ${data.sample_files.join(', ')}`
          : 'No direct files in this folder (click a subfolder below):';

        const subDiv = document.getElementById('browserSubdirs');
        subDiv.innerHTML = '';
        (data.subdirectories || []).forEach(sub => {
          const btn = document.createElement('span');
          btn.className = 'folder-item';
          btn.textContent = '📁 ' + sub.name;
          btn.onclick = () => browseTo(sub.path);
          subDiv.appendChild(btn);
        });
      } catch (e) {}
    }

    function browseUp() {
      if (parentBrowsedPath) browseTo(parentBrowsedPath);
    }

    async function useBrowsedFolder() {
      document.getElementById('pcPathInput').value = currentBrowsedPath;
      document.getElementById('pcBrowserBox').style.display = 'none';
      clearPickedFiles();
      await attestSelectedDirectory();
      await prevalidateSelectedDirectory();
    }

    async function loadPcFoldersDropdown() {
      try {
        const res = await fetch('/v1/admin/pc-folders', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } });
        if (!res.ok) return;
        const data = await res.json();
        const sel = document.getElementById('pcFolderSelect');
        sel.innerHTML = '';
        (data.folders || []).forEach(f => {
          const opt = document.createElement('option');
          opt.value = f.path;
          opt.textContent = f.label;
          sel.appendChild(opt);
        });
        if (sel.value) {
          document.getElementById('pcPathInput').value = sel.value;
          await loadSubdirectoriesIntoSelect(sel.value);
        }
      } catch (e) {}
    }

    let isAttesting = false;

    async function attestSelectedDirectory() {
      if (isAttesting) return;
      isAttesting = true;
      const btn = document.getElementById('runAttestBtn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Running Attestation on Directory...';
      }
      document.getElementById('attestStatusText').textContent = 'Scanning & signing files...';
      document.getElementById('attestEnglishBanner').innerHTML = '<strong>Scanning &amp; signing files in directory...</strong>';
      try {
        const maxFilesVal = parseInt(document.getElementById('demoMaxFilesSelect')?.value ?? '120', 10);
        const includeCodeVal = Boolean(document.getElementById('demoIncludeCodeChk')?.checked);
        const body = browserPickedFiles
          ? { files: browserPickedFiles }
          : { directory_path: document.getElementById('pcPathInput').value, max_files: maxFilesVal, include_code_dirs: includeCodeVal };

        const resp = await fetch('/v1/admin/attest-directory', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
          body: JSON.stringify(body)
        });
        const rawText = await resp.text();
        let data = {};
        try {
          data = JSON.parse(rawText);
        } catch (parseErr) {
          data = { detail: rawText || `HTTP ${resp.status}` };
        }
        if (!resp.ok) {
          document.getElementById('attestStatusText').textContent = 'Error: ' + (data.detail || resp.status);
          document.getElementById('attestEnglishBanner').textContent = 'Error: ' + (data.detail || resp.status);
          if (btn) {
            btn.disabled = false;
            btn.textContent = '1. Run Attestation on Directory (Engine)';
          }
          return;
        }
        const stamp = new Date().toLocaleTimeString();
        document.getElementById('attestStatusText').textContent = `✔ Attested ${data.attested_active_count} of ${data.total_files_found} file(s) at ${stamp}`;
        document.getElementById('attestEnglishBanner').innerHTML = `<strong>Verifiable Attestation Count (${stamp}):</strong> ${data.english_summary}`;
        document.getElementById('attTotal').textContent = data.total_files_found;
        document.getElementById('attActive').textContent = data.attested_active_count;
        document.getElementById('attHeld').textContent = data.held_in_review_count;

        const tbody = document.querySelector('#attestedFilesTable tbody');
        tbody.innerHTML = '';
        (data.files || []).forEach(f => {
          if (f.locator) {
            fileInspectorCache[f.locator] = Object.assign({}, fileInspectorCache[f.locator] || {}, f);
          }
          const tr = document.createElement('tr');
          const safeLoc = String(f.locator || '').replace(/'/g, "\\'");
          const ownerShort = f.owner || 'fileshare-owners@example.org';
          tr.innerHTML = `<td><a class="file-link" title="Click to inspect all 32 classification, ownership, policy & DSSE fields" onclick="openFileInspector('${safeLoc}')">&#128269; ${f.file_name}</a></td>
            <td><code style="color:#93c5fd;">${ownerShort}</code></td>
            <td><code>${f.object_type}</code></td>
            <td><span class="badge badge-${f.tier}">${f.tier}</span></td>
            <td><code>${f.ai_eligibility} / ${f.egress_class}</code></td>
            <td><code>${(f.content_sha256 || '').slice(0, 12)}…</code></td>`;
          tbody.appendChild(tr);
        });
        if (btn) {
          btn.textContent = `✔ Attested (${data.attested_active_count}/${data.total_files_found}) — 1. Run Attestation on Directory`;
        }
        await prevalidateSelectedDirectory();
      } catch (err) {
        document.getElementById('attestStatusText').textContent = 'Error: ' + err;
      } finally {
        isAttesting = false;
        if (btn) {
          btn.disabled = false;
        }
      }
    }

    async function dropUnattestedFile() {
      const dirPath = document.getElementById('pcPathInput').value;
      const resp = await fetch('/v1/admin/add-unattested-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({ directory_path: dirPath })
      });
      const data = await resp.json();
      if (resp.ok) {
        clearPickedFiles();
        await prevalidateSelectedDirectory();
      }
    }

    async function prevalidateSelectedDirectory() {
      document.getElementById('prevalStatusText').textContent = 'Scanning directory against signed snapshot...';
      const callerKey = document.getElementById('dirCallerKey').value.toLowerCase();
      const model = document.getElementById('dirModelSelect').value;
      const maxFilesVal = parseInt(document.getElementById('demoMaxFilesSelect')?.value ?? '120', 10);
      const includeCodeVal = Boolean(document.getElementById('demoIncludeCodeChk')?.checked);
      const body = browserPickedFiles
        ? { files: browserPickedFiles, caller_key: callerKey, model }
        : { directory_path: document.getElementById('pcPathInput').value, caller_key: callerKey, model, max_files: maxFilesVal, include_code_dirs: includeCodeVal };

      const resp = await fetch('/v1/prevalidate-directory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await resp.json();
      if (!resp.ok) {
        document.getElementById('prevalStatusText').textContent = 'Error: ' + (data.detail || resp.status);
        document.getElementById('prevalEnglishBanner').textContent = 'Error: ' + (data.detail || resp.status);
        return;
      }

      document.getElementById('prevalStatusText').textContent = `${data.passed_count} Passed / ${data.failed_count} Did Not Pass`;
      const banner = document.getElementById('prevalEnglishBanner');
      banner.innerHTML = `<strong>Verifiable Prevalidator Count:</strong> ${data.english_summary}`;
      banner.className = 'english-verdict' + (data.failed_count > 0 ? ' has-failures' : '');

      document.getElementById('pvTotal').textContent = data.total_files;
      document.getElementById('pvPassed').textContent = data.passed_count;
      document.getElementById('pvFailed').textContent = data.failed_count;
      document.getElementById('pvUnattested').textContent = data.unattested_count;

      const tbody = document.querySelector('#prevalidatedFilesTable tbody');
      tbody.innerHTML = '';
      (data.files || []).forEach(f => {
        if (f.locator) {
          fileInspectorCache[f.locator] = Object.assign({}, fileInspectorCache[f.locator] || {}, {
            locator: f.locator,
            file_name: f.file_name,
            observed_sha256: f.observed_sha256,
            attestation_state: f.attestation_state,
            preval_verdict: f.verdict,
            preval_passed: f.passed,
            preval_reason_detail: f.reason_detail,
            preval_reason_codes: f.reason_codes || []
          });
        }
        const tr = document.createElement('tr');
        const verdictBadge = f.verdict.startsWith('OBSERVED') ? 'badge-Confidential' : (f.passed ? 'badge-PASS' : 'badge-FAIL');
        const tierBadge = f.tier && f.tier !== 'NONE' ? `badge-${f.tier}` : 'badge-FAIL';
        const safeLoc = String(f.locator || '').replace(/'/g, "\\'");
        tr.innerHTML = `<td><a class="file-link" title="Click to inspect full classification, ownership & Prevalidator verdict" onclick="openFileInspector('${safeLoc}')">&#128269; ${f.file_name}</a></td>
          <td><code>${f.attestation_state}</code></td>
          <td><span class="badge ${tierBadge}">${f.tier || 'UNATTESTED'}</span></td>
          <td><span class="badge ${verdictBadge}">${f.verdict}</span></td>
          <td><code>${f.reason_detail}</code></td>`;
        tbody.appendChild(tr);
      });
      await refreshState();
    }

    function loadPreset(name) {
      if (name === 'allow') {
        document.getElementById('endpointSelect').value = '/v1/chat/completions';
        document.getElementById('callerKey').value = 'pod-key-public';
        document.getElementById('modelSelect').value = 'gpt-4o';
        document.getElementById('promptInput').value = 'Summarize this architecture doc:\\n<pod:object locator="file://estate/fileshare/product_overview_public.md">Open Source AI Architecture Overview</pod:object>';
      } else if (name === 'strip') {
        document.getElementById('endpointSelect').value = '/v1/messages';
        document.getElementById('callerKey').value = 'pod-key-confidential';
        document.getElementById('modelSelect').value = 'local-model';
        document.getElementById('promptInput').value = 'Provide general HR policy guidance.\\n<pod:object locator="file://estate/fileshare/dept_compensation_confidential.xlsx">diana.prince@example.org | salary: $145,000</pod:object>';
      } else if (name === 'restricted') {
        document.getElementById('endpointSelect').value = '/v1/chat/completions';
        document.getElementById('callerKey').value = 'pod-key-restricted';
        document.getElementById('modelSelect').value = 'gpt-4o';
        document.getElementById('promptInput').value = 'Analyze intake record:\\n<pod:object locator="file://estate/fileshare/clinical_intake_restricted.txt">Patient SSN: 412-58-9021, MRN-8839201</pod:object>';
      } else if (name === 'unattested') {
        document.getElementById('endpointSelect').value = '/v1/chat/completions';
        document.getElementById('callerKey').value = 'pod-key-public';
        document.getElementById('modelSelect').value = 'gpt-4o';
        document.getElementById('promptInput').value = '<pod:object locator="file://estate/fileshare/unverified_notes_ambiguous.txt">AMBIGUOUS_REF_9042</pod:object>';
      }
    }

    async function refreshState() {
      const h = await (await fetch('/healthz')).json();
      currentMode = h.mode;
      if (h.latency) {
        renderLatencyClock(h.latency);
      }
      const badge = document.getElementById('modeBadge');
      badge.textContent = currentMode === 'enforce' ? 'ENFORCE MODE (BLOCKING)' : 'OBSERVE MODE (AUDIT-ONLY)';
      badge.className = 'badge ' + (currentMode === 'enforce' ? 'badge-Public' : 'badge-Confidential');
      const modeBtn = document.getElementById('toggleModeBtn');
      if (modeBtn) {
        if (currentMode === 'enforce') {
          modeBtn.style.background = '#059669';
          modeBtn.style.color = '#ffffff';
          modeBtn.innerHTML = '&#128737; Mode: ENFORCE (Click &rarr; Observe)';
        } else {
          modeBtn.style.background = '#d97706';
          modeBtn.style.color = '#ffffff';
          modeBtn.innerHTML = '&#128065; Mode: OBSERVE (Click &rarr; Enforce)';
        }
      }

      const snapResp = await (await fetch('/v1/admin/snapshot-view', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } })).json();
      if (snapResp.snapshot) {
        const s = snapResp.snapshot;
        document.getElementById('snapMeta').textContent = `Snapshot ID: ${s.snapshot_id} | Sequence: #${s.sequence_number} | Total Entries: ${Object.keys(s.entries).length} | Expires: ${s.expires_at}`;
        const tbody = document.querySelector('#entriesTable tbody');
        tbody.innerHTML = '';
        Object.values(s.entries).forEach(e => {
          if (e.locator) {
            fileInspectorCache[e.locator] = Object.assign({}, fileInspectorCache[e.locator] || {}, e);
          }
          const tr = document.createElement('tr');
          const safeLoc = String(e.locator || '').replace(/'/g, "\\'");
          tr.innerHTML = `<td><a class="file-link" title="Click to inspect full attestation statement & ownership" onclick="openFileInspector('${safeLoc}')">&#128269; <code>${e.locator}</code></a></td>
            <td><span class="badge badge-${e.tier}">${e.tier}</span></td>
            <td>${e.minimum_clearance}</td>
            <td><code>${e.egress_class}</code></td>
            <td><code>${e.ai_eligibility}</code></td>
            <td><code>${e.content_sha256.slice(0, 10)}…</code></td>`;
          tbody.appendChild(tr);
        });
      }

      const auditResp = await (await fetch('/v1/admin/audit-log', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } })).json();
      const atbody = document.querySelector('#auditTable tbody');
      atbody.innerHTML = '';
      auditResp.entries.slice().reverse().slice(0, 10).forEach(a => {
        const tr = document.createElement('tr');
        const latMs = typeof a.decision_latency_ms === 'number' ? a.decision_latency_ms.toFixed(3) + ' ms' : '-';
        const latUs = typeof a.decision_latency_us === 'number' ? ` (${a.decision_latency_us.toFixed(0)} µs)` : '';
        tr.innerHTML = `<td><code>${a.timestamp.slice(11, 19)}</code></td>
          <td>${a.mode}</td>
          <td><strong>${a.decision}</strong></td>
          <td><code style="color:#34d399; font-weight:700;">${latMs}${latUs}</code></td>
          <td><code>${(a.reason_codes || []).join(', ') || 'NONE'}</code></td>
          <td>${a.caller_clearance} / <code>${a.target_egress}</code></td>`;
        atbody.appendChild(tr);
      });
    }

    function renderLatencyClock(lat) {
      if (!lat) return;
      const lastMs = Number(lat.last_decision_ms || 0);
      const lastUs = Number(lat.last_decision_us || 0);
      document.getElementById('latClockDigital').textContent = `${lastMs.toFixed(3)} ms`;
      document.getElementById('latClockMicro').innerHTML = `${lastUs.toFixed(1)} &mu;s &bull; 0 DB Calls`;
      document.getElementById('latP50').textContent = `${Number(lat.p50_ms || 0).toFixed(3)} ms`;
      document.getElementById('latAvg').textContent = `${Number(lat.avg_ms || 0).toFixed(3)} ms`;
      document.getElementById('latP95').textContent = `${Number(lat.p95_ms || 0).toFixed(3)} ms`;
      document.getElementById('latP99').textContent = `${Number(lat.p99_ms || 0).toFixed(3)} ms`;
      document.getElementById('latTotalChecks').textContent = lat.total_evaluations || 0;

      const headerPill = document.getElementById('headerLatencyPill');
      if (headerPill) {
        headerPill.innerHTML = `&#9201; Gate: ${lastMs.toFixed(3)} ms (P95: ${Number(lat.p95_ms || 0).toFixed(2)} ms)`;
      }

      const slaBadge = document.getElementById('latSlaBadge');
      if (slaBadge) {
        const pct = Number(lat.sla_compliant_pct ?? 100);
        slaBadge.textContent = `SLA ≤ 5.0 ms: ${pct.toFixed(1)}% PASS`;
        slaBadge.className = 'badge ' + (pct >= 99 ? 'badge-Public' : 'badge-Confidential');
      }

      const dirScan = lat.last_directory_scan || {};
      if (dirScan.total_files > 0) {
        document.getElementById('latDirEnforcer').textContent = `${Number(dirScan.in_memory_enforcer_ms || 0).toFixed(2)} ms`;
        document.getElementById('latDirPerFile').innerHTML = `${Number(dirScan.avg_per_file_us || 0).toFixed(1)} &mu;s / file (${dirScan.total_files} files)`;
        document.getElementById('latThroughput').textContent = `${Math.round(Number(dirScan.files_per_sec || 0)).toLocaleString()} /s`;
        document.getElementById('latDirWall').textContent = `Disk+SHA256: ${Number(dirScan.total_wall_ms || 0).toFixed(1)} ms`;
      }

      const spark = document.getElementById('latSparkline');
      if (spark) {
        spark.innerHTML = '';
        const samples = lat.recent_samples_ms || [];
        const maxVal = Math.max(1.0, ...samples);
        samples.forEach((val, idx) => {
          const pctHeight = Math.max(14, Math.min(100, Math.round((val / maxVal) * 100)));
          const color = val <= 1.0 ? '#10b981' : (val <= 5.0 ? '#f59e0b' : '#ef4444');
          const bar = document.createElement('div');
          bar.title = `Eval #${idx + 1}: ${val.toFixed(3)} ms (${(val * 1000).toFixed(1)} µs)`;
          bar.style.cssText = `flex:1; max-width:22px; height:${pctHeight}%; background:${color}; border-radius:3px 3px 0 0; position:relative; cursor:pointer;`;
          spark.appendChild(bar);
        });
      }
    }

    async function runLatencyBenchmark() {
      const btn = document.getElementById('benchBtn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Benchmarking 100 Evaluations...';
      }
      try {
        const resp = await fetch('/v1/admin/latency-benchmark', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
          body: JSON.stringify({ iterations: 100 })
        });
        const data = await resp.json();
        if (resp.ok && data.latency) {
          renderLatencyClock(data.latency);
          await refreshState();
        }
        if (btn && data.benchmark_wall_ms !== undefined) {
          btn.textContent = `✔ 100 Evals in ${Number(data.benchmark_wall_ms).toFixed(2)} ms (${Number(data.avg_eval_us).toFixed(1)} µs/eval)`;
        }
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    async function toggleMode() {
      const next = currentMode === 'enforce' ? 'observe' : 'enforce';
      await fetch('/v1/admin/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({ mode: next })
      });
      await refreshState();
      await prevalidateSelectedDirectory();
    }

    async function sendRequest() {
      const ep = document.getElementById('endpointSelect').value;
      const key = document.getElementById('callerKey').value;
      const model = document.getElementById('modelSelect').value;
      const content = document.getElementById('promptInput').value;
      const resp = await fetch(ep, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Caller-Key': key },
        body: JSON.stringify({ model, messages: [{ role: 'user', content }] })
      });
      const data = await resp.json();
      document.getElementById('statusSpan').textContent = `HTTP ${resp.status}`;
      document.getElementById('responseBox').textContent = JSON.stringify(data, null, 2);
      await refreshState();
    }

    const LLM_PRESETS = {
      builtin: { name: 'Built-in G1 Gateway', protocol: 'openai', base_url: 'http://litellm-gateway:4000', default_model: 'local-model', egress_class: 'local_only' },
      lmstudio: { name: 'LM Studio (Host PC)', protocol: 'openai', base_url: 'http://host.docker.internal:1234', default_model: 'local-model', egress_class: 'local_only' },
      ollama: { name: 'Ollama (Host PC)', protocol: 'openai', base_url: 'http://host.docker.internal:11434', default_model: 'llama3.2', egress_class: 'local_only' },
      litellm_host: { name: 'LiteLLM / vLLM (Host PC)', protocol: 'openai', base_url: 'http://host.docker.internal:4000', default_model: 'vpc-model', egress_class: 'private_cloud' },
      openai: { name: 'OpenAI Cloud API', protocol: 'openai', base_url: 'https://api.openai.com', default_model: 'gpt-4o', egress_class: 'public_api' },
      anthropic: { name: 'Anthropic Cloud API', protocol: 'anthropic', base_url: 'https://api.anthropic.com', default_model: 'claude-3-5-sonnet-latest', egress_class: 'public_api' },
      gemini: { name: 'Google Gemini OpenAI API', protocol: 'openai', base_url: 'https://generativelanguage.googleapis.com/v1beta/openai', default_model: 'gemini-2.5-flash', egress_class: 'public_api' }
    };

    function toggleLlmConfig() {
      const drawer = document.getElementById('llmConfigDrawer');
      drawer.style.display = drawer.style.display === 'none' ? 'block' : 'none';
    }

    function applyLlmPreset() {
      const key = document.getElementById('llmPresetSelect').value;
      const p = LLM_PRESETS[key];
      if (!p) return;
      document.getElementById('llmProviderName').value = p.name;
      document.getElementById('llmProtocol').value = p.protocol;
      document.getElementById('llmBaseUrl').value = p.base_url;
      document.getElementById('llmDefaultModel').value = p.default_model;
      document.getElementById('llmEgressClass').value = p.egress_class;
    }

    function ensureModelInDropdowns(modelId, egressClass) {
      if (!modelId) return;
      ['dirModelSelect', 'modelSelect'].forEach(selId => {
        const sel = document.getElementById(selId);
        if (!sel) return;
        const exists = Array.from(sel.options).some(o => o.value === modelId);
        if (!exists) {
          const opt = document.createElement('option');
          opt.value = modelId;
          opt.textContent = `${modelId} (${egressClass || 'configured'})`;
          sel.insertBefore(opt, sel.firstChild);
        }
        sel.value = modelId;
      });
    }

    async function loadLlmConfig() {
      try {
        const resp = await fetch('/v1/admin/llm-config', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } });
        if (!resp.ok) return;
        const cfg = await resp.json();
        document.getElementById('llmProviderName').value = cfg.provider_name || 'Built-in G1 Gateway';
        document.getElementById('llmProtocol').value = cfg.protocol || 'openai';
        document.getElementById('llmBaseUrl').value = cfg.base_url || 'http://litellm-gateway:4000';
        document.getElementById('llmDefaultModel').value = cfg.default_model || 'local-model';
        document.getElementById('llmEgressClass').value = cfg.egress_class || 'local_only';
        document.getElementById('activeLlmBadge').textContent = `LLM: ${cfg.provider_name} (${cfg.default_model} • ${cfg.egress_class})`;
        document.getElementById('llmConfigStatus').textContent = `Active Provider: ${cfg.provider_name} -> ${cfg.base_url} [Model: ${cfg.default_model}, Egress: ${cfg.egress_class}, API Key: ${cfg.has_api_key ? cfg.api_key_masked : 'none'}]`;
        ensureModelInDropdowns(cfg.default_model, cfg.egress_class);
        if (cfg.protocol === 'anthropic') {
          document.getElementById('endpointSelect').value = '/v1/messages';
        } else {
          document.getElementById('endpointSelect').value = '/v1/chat/completions';
        }
      } catch (e) {}
    }

    async function saveLlmConfig() {
      const payload = {
        provider_name: document.getElementById('llmProviderName').value.trim(),
        protocol: document.getElementById('llmProtocol').value,
        base_url: document.getElementById('llmBaseUrl').value.trim(),
        default_model: document.getElementById('llmDefaultModel').value.trim(),
        egress_class: document.getElementById('llmEgressClass').value,
        api_key: document.getElementById('llmApiKey').value.trim()
      };
      const statusEl = document.getElementById('llmConfigStatus');
      statusEl.style.color = '#93c5fd';
      statusEl.textContent = 'Saving LLM provider configuration...';
      const resp = await fetch('/v1/admin/llm-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();
      if (!resp.ok) {
        statusEl.style.color = '#f87171';
        statusEl.textContent = 'Error saving config: ' + (data.detail || resp.status);
        return;
      }
      statusEl.style.color = '#34d399';
      statusEl.textContent = `✔ Saved & Activated: ${data.provider_name} (${data.base_url}) — Model '${data.default_model}' mapped to egress '${data.egress_class}'`;
      document.getElementById('activeLlmBadge').textContent = `LLM: ${data.provider_name} (${data.default_model} • ${data.egress_class})`;
      ensureModelInDropdowns(data.default_model, data.egress_class);
      if (data.protocol === 'anthropic') {
        document.getElementById('endpointSelect').value = '/v1/messages';
      } else {
        document.getElementById('endpointSelect').value = '/v1/chat/completions';
      }
    }

    async function testLlmConfig() {
      const payload = {
        provider_name: document.getElementById('llmProviderName').value.trim(),
        protocol: document.getElementById('llmProtocol').value,
        base_url: document.getElementById('llmBaseUrl').value.trim(),
        default_model: document.getElementById('llmDefaultModel').value.trim(),
        egress_class: document.getElementById('llmEgressClass').value,
        api_key: document.getElementById('llmApiKey').value.trim()
      };
      const statusEl = document.getElementById('llmConfigStatus');
      statusEl.style.color = '#fbbf24';
      statusEl.textContent = `Testing connection to ${payload.base_url}...`;
      const resp = await fetch('/v1/admin/llm-config/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();
      if (!resp.ok || !data.reachable) {
        statusEl.style.color = '#f87171';
        statusEl.textContent = `✖ Connection failed: ${data.error || data.detail || 'Unreachable'}`;
        return;
      }
      statusEl.style.color = '#34d399';
      const modelsStr = (data.discovered_models && data.discovered_models.length)
        ? ` | Discovered models: ${data.discovered_models.slice(0, 6).join(', ')}`
        : '';
      statusEl.textContent = `✔ Connected to ${data.base_url} in ${data.latency_ms} ms (HTTP ${data.status_code})${modelsStr}`;
      (data.discovered_models || []).forEach(m => ensureModelInDropdowns(m, payload.egress_class));
    }

    let crawlerRunning = true;
    let lastRenderedSnapshotSeq = null;

    function toggleEnterpriseScannerDrawer() {
      const drawer = document.getElementById('enterpriseScannerDrawer');
      if (!drawer) return;
      if (drawer.style.display === 'none' || !drawer.style.display) {
        drawer.style.display = 'block';
        refreshCrawlerTelemetry(true);
      } else {
        drawer.style.display = 'none';
      }
    }

    function renderCrawlerTargetCheckboxes(targets) {
      const box = document.getElementById('crawlerTargetCheckboxes');
      if (!box || !Array.isArray(targets)) return;
      box.innerHTML = '';
      targets.forEach((t, idx) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:5px 6px; border-bottom:1px solid #1e293b; font-size:12px;';
        const left = document.createElement('label');
        left.style.cssText = 'display:flex; align-items:center; gap:8px; cursor:pointer; flex:1;';
        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.className = 'crawler-target-chk';
        chk.dataset.uri = t.path_or_uri;
        chk.checked = Boolean(t.enabled);
        const span = document.createElement('span');
        span.textContent = t.label || t.path_or_uri;
        left.appendChild(chk);
        left.appendChild(span);

        const focusBtn = document.createElement('button');
        focusBtn.className = 'btn btn-dark';
        focusBtn.style.cssText = 'padding:3px 8px; font-size:11px;';
        focusBtn.textContent = '🎯 Sweep Only This';
        focusBtn.onclick = async () => {
          await controlContinuousCrawler({ focus_only_target: t.path_or_uri });
          renderCrawlerTargetCheckboxes((await (await fetch('/v1/admin/crawler/status', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } })).json()).targets);
        };
        row.appendChild(left);
        row.appendChild(focusBtn);
        box.appendChild(row);
      });
    }

    async function controlContinuousCrawler(payload) {
      try {
        const resp = await fetch('/v1/admin/crawler/control', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
          body: JSON.stringify(payload)
        });
        if (!resp.ok) return;
        const data = await resp.json();
        applyCrawlerTelemetryToDom(data, false);
      } catch (e) {}
    }

    async function toggleContinuousCrawlerRun() {
      await controlContinuousCrawler({ running: !crawlerRunning });
    }

    async function stopContinuousCrawler() {
      await controlContinuousCrawler({ stop_scan: true, running: false });
    }

    async function resetCrawlerWatermarks() {
      await controlContinuousCrawler({ reset_watermarks: true, running: true });
    }

    async function sweepSelectedTargetUnbounded() {
      const targetUri = document.getElementById('pcPathInput').value;
      await controlContinuousCrawler({ focus_only_target: targetUri, running: true });
    }

    async function saveCrawlerTargetsSelection() {
      const chks = Array.from(document.querySelectorAll('.crawler-target-chk'));
      const targets = chks.map(c => ({ path_or_uri: c.dataset.uri, enabled: c.checked }));
      await controlContinuousCrawler({ targets });
    }

    async function addCrawlerTarget() {
      const inp = document.getElementById('newCrawlerTargetUri');
      const uri = (inp.value || '').trim();
      if (!uri) return;
      inp.value = '';
      await controlContinuousCrawler({ add_target_uri: uri, running: true });
      await refreshCrawlerTelemetry(true);
    }

    async function saveCrawlerPolicySettings() {
      const micro_publish_delta_threshold = parseInt(document.getElementById('crawlerMicroBatchSelect').value, 10);
      const throttle_ms_per_file = parseFloat(document.getElementById('crawlerThrottleSelect').value);
      const include_code_dirs = Boolean(document.getElementById('crawlerIncludeCodeChk').checked);
      const auto_revoke_deleted = Boolean(document.getElementById('crawlerAutoRevokeChk').checked);
      await controlContinuousCrawler({
        micro_publish_delta_threshold,
        throttle_ms_per_file,
        include_code_dirs,
        auto_revoke_deleted
      });
    }

    function applyCrawlerTelemetryToDom(data, renderTargets = false) {
      if (!data) return;
      crawlerRunning = Boolean(data.running);
      const badge = document.getElementById('crawlerStateBadge');
      const btn = document.getElementById('crawlerToggleBtn');
      const stopBtn = document.getElementById('crawlerStopBtn');
      const statusText = String(data.status_label || (crawlerRunning ? 'SWEEPING' : 'STOPPED'));
      const isStopped = !crawlerRunning && statusText.startsWith('STOPPED');
      if (badge) {
        badge.textContent = statusText;
        badge.className = 'badge ' + (crawlerRunning ? 'badge-Public' : (isStopped ? 'badge-FAIL' : 'badge-Confidential'));
      }
      if (btn) {
        if (crawlerRunning) {
          btn.innerHTML = '&#9208; Pause Continuous Scanner';
          btn.className = 'btn btn-amber';
        } else {
          btn.innerHTML = '&#9654; Start Enterprise Scan';
          btn.className = 'btn btn-green';
        }
      }
      if (stopBtn) {
        stopBtn.disabled = !crawlerRunning && isStopped;
        stopBtn.style.opacity = (!crawlerRunning && isStopped) ? '0.55' : '1';
      }

      document.getElementById('crFilesSwept').textContent = Number(data.files_swept || 0).toLocaleString();
      document.getElementById('crPassNum').textContent = `Pass #${data.pass_number || 1} • Watermarks: ${Number(data.watermark_count || 0).toLocaleString()}`;
      document.getElementById('crSkipped').textContent = Number(data.unchanged_skipped || 0).toLocaleString();
      document.getElementById('crDeltas').textContent = Number(data.deltas_attested || 0).toLocaleString();
      document.getElementById('crRevoked').textContent = `Pass 2 Deep Scan • Revoked: ${data.deleted_revoked || 0}`;
      document.getElementById('crRate').textContent = `~${Number(data.scan_rate_files_per_sec || 0).toFixed(1)} /s`;
      document.getElementById('crTargetNow').textContent = `Target: ${data.current_target || '-'}`;
      document.getElementById('crSnapshots').textContent = `${data.micro_snapshots_published || 0}${data.last_snapshot_seq ? ' (#' + data.last_snapshot_seq + ')' : ''}`;
      document.getElementById('crPendingDeltas').textContent = `Pending flush: ${data.pending_deltas || 0} deltas`;
      document.getElementById('crCurrentHeadFile').textContent = data.current_file || 'Idle';

      const streamEl = document.getElementById('crTickerStream');
      if (streamEl && Array.isArray(data.ticker_feed)) {
        streamEl.innerHTML = data.ticker_feed.map(item => {
          const safeLoc = String(item.locator || '').replace(/'/g, "\\'");
          const clickablePath = item.locator
            ? `<a class="file-link" style="padding:0 5px;font-size:11.5px;" onclick="openFileInspector('${safeLoc}')">&#128269; ${item.path}</a>`
            : `<span>${item.path}</span>`;
          if (item.kind === 'delta') {
            return `<div style="color:#34d399;">[${item.timestamp}] ⚡ <strong>[ATTESTING DELTA]</strong> ${clickablePath} &rarr; <span class="badge badge-${item.tier || 'Internal'}" style="padding:1px 6px;font-size:10px;">${item.tier || ''}</span> <span style="color:#94a3b8;">(${item.detail}${item.sha256 ? ' • sha256: ' + item.sha256 : ''})</span></div>`;
          } else if (item.kind === 'snapshot') {
            return `<div style="color:#a78bfa; font-weight:700;">[${item.timestamp}] 📦 [ROLLING MICRO-SNAPSHOT] ${item.path} — ${item.detail}</div>`;
          } else if (item.kind === 'stop') {
            return `<div style="color:#f87171; font-weight:700;">[${item.timestamp}] 🛑 [ENTERPRISE SCAN STOPPED] ${item.path} — ${item.detail}</div>`;
          } else if (item.kind === 'revoke') {
            return `<div style="color:#f87171; font-weight:700;">[${item.timestamp}] 🚫 [REVOKED DELETED] ${clickablePath} — ${item.detail}</div>`;
          } else {
            return `<div style="color:#64748b;">[${item.timestamp}] ⏭ [UNCHANGED SKIP] ${clickablePath} (${item.detail})</div>`;
          }
        }).join('');
      }

      if (renderTargets && Array.isArray(data.targets)) {
        renderCrawlerTargetCheckboxes(data.targets);
      }

      if (data.last_snapshot_seq && data.last_snapshot_seq !== lastRenderedSnapshotSeq) {
        lastRenderedSnapshotSeq = data.last_snapshot_seq;
        refreshState();
      }
    }

    async function refreshCrawlerTelemetry(renderTargets = false) {
      try {
        const resp = await fetch('/v1/admin/crawler/status', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } });
        if (!resp.ok) return;
        const data = await resp.json();
        applyCrawlerTelemetryToDom(data, renderTargets);
      } catch (e) {}
    }

    const fileInspectorCache = {};
    let currentlyInspectedLocator = null;
    let currentlyInspectedFullPayload = null;

    function closeFileInspector() {
      const modal = document.getElementById('fileInspectorModal');
      if (modal) modal.style.display = 'none';
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeFileInspector();
    });

    function renderInspectorFields(locator, cached, apiData) {
      const rec = (apiData && apiData.record) || {};
      const pred = (apiData && apiData.predicate) || (rec.statement && rec.statement.predicate) || {};
      const ident = pred.identity || {};
      const own = pred.ownership || {};
      const prov = pred.provenance || {};
      const integ = pred.integrity || {};
      const classif = pred.classification || {};
      const hand = pred.handling || {};
      const pol = hand.policy || {};
      const life = pred.lifecycle || {};
      const env = (apiData && apiData.dsse_envelope) || rec.dsse_envelope || null;
      const snapEntry = (apiData && apiData.snapshot_entry) || null;
      const isFound = Boolean((apiData && (apiData.found || apiData.held_in_review)) || cached.record_id || cached.content_sha256);

      const fileName = ident.display_name || cached.display_name || cached.file_name || (locator ? locator.split('/').pop() : locator);
      const tier = classif.tier || rec.tier || cached.tier || (snapEntry && snapEntry.tier) || 'UNATTESTED';
      const statusStr = life.status || rec.status || cached.status || cached.attestation_state || (isFound ? 'issued' : 'UNATTESTED (NO SIGNED RECORD)');

      document.getElementById('inspTitle').textContent = fileName;
      document.getElementById('inspLocator').textContent = locator;

      const tierBadge = document.getElementById('inspTierBadge');
      tierBadge.textContent = tier;
      tierBadge.className = 'badge ' + (tier && tier !== 'NONE' && tier !== 'UNATTESTED' ? `badge-${tier}` : 'badge-FAIL');

      const statusBadge = document.getElementById('inspStatusBadge');
      statusBadge.textContent = String(statusStr).toUpperCase();
      statusBadge.className = 'badge ' + (String(statusStr).toLowerCase().includes('unattested') || String(statusStr).toLowerCase().includes('revoked') ? 'badge-FAIL' : 'badge-Internal');

      const prevalBadge = document.getElementById('inspPrevalBadge');
      if (cached.preval_verdict) {
        prevalBadge.style.display = 'inline-block';
        prevalBadge.textContent = `Prevalidator: ${cached.preval_verdict}`;
        prevalBadge.className = 'badge ' + (cached.preval_passed ? 'badge-PASS' : 'badge-FAIL');
      } else if (snapEntry) {
        prevalBadge.style.display = 'inline-block';
        prevalBadge.textContent = `Snapshot Gate: ${snapEntry.ai_eligibility.toUpperCase()}`;
        prevalBadge.className = 'badge badge-PASS';
      } else {
        prevalBadge.style.display = 'none';
      }

      const banner = document.getElementById('inspBanner');
      if (!isFound && (!tier || tier === 'NONE' || tier === 'UNATTESTED')) {
        banner.className = 'english-verdict has-failures';
        banner.innerHTML = `<strong>&#9888; UNATTESTED OBJECT (Fail-Closed Default Deny):</strong> <code>${fileName}</code> exists in the target directory/store (` +
          `observed SHA-256: <code>${(cached.observed_sha256 || 'unhashed').slice(0, 16)}…</code>), but has <strong>NO signed attestation record</strong> in the Registry or Active Snapshot. ` +
          `The Prevalidator blocks all AI requests referencing this object until you click <strong>1. Run Attestation on Directory (Engine)</strong>.`;
      } else {
        banner.className = 'english-verdict';
        const ownerVal = own.owner || rec.owner || cached.owner || 'fileshare-owners@example.org';
        const stewardVal = own.steward || cached.steward || 'data-governance-steward@contoso.com';
        const aiRuleVal = pol.ai_eligibility || rec.ai_eligibility || cached.ai_eligibility || (snapEntry && snapEntry.ai_eligibility) || 'deny';
        const egressVal = pol.egress_class || rec.egress_class || cached.egress_class || (snapEntry && snapEntry.egress_class) || 'local_only';
        banner.innerHTML = `<strong>&#10004; Signed POD Attestation Record:</strong> <code>${fileName}</code> is owned by <strong>${ownerVal}</strong> (Steward: <strong>${stewardVal}</strong>), ` +
          `classified as <strong>${tier}</strong> (${((Number(classif.confidence ?? rec.confidence ?? cached.confidence ?? 0.95)) * 100).toFixed(1)}% confidence via <code>${classif.classifier_engine || cached.classifier_engine || 'presidio'}</code>), ` +
          `with AI policy <code>ai_eligibility=${aiRuleVal}</code> and max egress <code>${egressVal}</code>.`;
      }

      // Group 1 & 2: Ownership & Identity
      document.getElementById('inspOwner').textContent = own.owner || rec.owner || cached.owner || (isFound ? 'fileshare-owners@example.org' : 'Unassigned (Unattested File)');
      document.getElementById('inspSteward').textContent = own.steward || cached.steward || (isFound ? 'data-governance-steward@contoso.com' : 'None — Awaiting Attestation');
      document.getElementById('inspOrgUnit').textContent = own.org_unit || cached.org_unit || (isFound ? 'Enterprise Data & AI Governance' : '-');
      document.getElementById('inspJurisdiction').textContent = own.jurisdiction || cached.jurisdiction || (isFound ? 'GLOBAL' : '-');
      document.getElementById('inspRecordId').textContent = ident.record_id || rec.record_id || cached.record_id || 'NONE (Unattested)';
      document.getElementById('inspObjTypeEnv').textContent = `${ident.object_type || rec.object_type || cached.object_type || 'file'} • ${ident.environment || cached.environment || 'production'}`;

      // Group 5: Classification & Sensitive Entities
      document.getElementById('inspClassTier').innerHTML = `<span class="badge ${tier && tier !== 'NONE' && tier !== 'UNATTESTED' ? 'badge-' + tier : 'badge-FAIL'}">${tier}</span>`;
      const confNum = Number(classif.confidence ?? rec.confidence ?? cached.confidence ?? (isFound ? 0.95 : 0));
      document.getElementById('inspConfidence').textContent = isFound ? `${(confNum * 100).toFixed(1)}% (${confNum.toFixed(4)})` : '0.0% (Not Scanned)';
      document.getElementById('inspClassifierEngine').textContent = classif.classifier_engine || cached.classifier_engine || (isFound ? 'presidio' : 'Not Scanned');

      const cats = classif.sensitive_categories || cached.sensitive_categories || [];
      const catsBox = document.getElementById('inspSensitiveCats');
      if (!isFound && (!tier || tier === 'NONE' || tier === 'UNATTESTED')) {
        catsBox.innerHTML = `<span style="color:#f87171;">&#9888; File has not been scanned by the Attestation Engine yet.</span>`;
      } else if (!Array.isArray(cats) || cats.length === 0) {
        catsBox.innerHTML = `<span style="color:#34d399;">&#10004; 0 Sensitive PII / PHI / PCI / Credential Entities Detected — Verified Clean (${tier})</span>`;
      } else {
        catsBox.innerHTML = cats.map(c => {
          const confStr = c.max_confidence !== undefined ? `${(Number(c.max_confidence) * 100).toFixed(0)}% conf` : '';
          const colStr = c.column_or_field ? ` • field: <code>${c.column_or_field}</code>` : '';
          return `<div style="display:flex; justify-content:space-between; align-items:center; padding:4px 6px; border-bottom:1px solid #1e293b;">
            <span><strong style="color:#fbbf24;">${c.category}</strong>${colStr}</span>
            <span><span class="badge badge-Confidential" style="font-size:10px;">Count: ${c.count}</span> <code style="color:#94a3b8;">${confStr}</code></span>
          </div>`;
        }).join('');
      }

      // Group 6: AI Handling & Policy
      const aiElig = pol.ai_eligibility || rec.ai_eligibility || cached.ai_eligibility || (snapEntry && snapEntry.ai_eligibility) || 'deny (fail-closed)';
      const minClear = pol.minimum_clearance || rec.minimum_clearance || cached.minimum_clearance || (snapEntry && snapEntry.minimum_clearance) || 'Restricted';
      const egressCls = pol.egress_class || rec.egress_class || cached.egress_class || (snapEntry && snapEntry.egress_class) || 'local_only';
      const allowRag = hand.allow_rag_indexing !== undefined ? hand.allow_rag_indexing : (cached.allow_rag_indexing !== undefined ? cached.allow_rag_indexing : (tier === 'Public' || tier === 'Internal'));
      const allowTrain = Boolean(hand.allow_model_training ?? cached.allow_model_training ?? false);
      const redactList = hand.redaction_categories || cached.redaction_categories || cats.map(c => c.category);

      document.getElementById('inspAiRule').innerHTML = `<code>${aiElig}</code>`;
      document.getElementById('inspMinClearance').innerHTML = `<span class="badge badge-${minClear}">${minClear}</span>`;
      document.getElementById('inspEgressClass').innerHTML = `<code>${egressCls}</code>`;
      document.getElementById('inspAllowRag').innerHTML = allowRag ? '<span style="color:#34d399;font-weight:700;">&#10004; Allowed (true)</span>' : '<span style="color:#f87171;font-weight:700;">&#10006; Blocked (false)</span>';
      document.getElementById('inspAllowTrain').innerHTML = allowTrain ? '<span style="color:#34d399;">Allowed (true)</span>' : '<span style="color:#94a3b8;">Prohibited (false)</span>';
      document.getElementById('inspRedactCats').textContent = (Array.isArray(redactList) && redactList.length > 0) ? redactList.join(', ') : 'None';

      // Group 4: Cryptographic Integrity & Chunks
      const attSha = integ.content_sha256 || rec.content_sha256 || cached.content_sha256 || (snapEntry && snapEntry.content_sha256) || '';
      const obsSha = cached.observed_sha256 || attSha || '';
      const textSha = integ.extracted_text_sha256 || rec.extracted_text_sha256 || cached.extracted_text_sha256 || (snapEntry && snapEntry.extracted_text_sha256) || '';
      const schemaSha = integ.schema_sha256 || rec.schema_sha256 || cached.schema_sha256 || (snapEntry && snapEntry.schema_sha256) || '';
      const chunks = integ.chunk_hashes || rec.chunk_hashes || cached.chunk_hashes || (snapEntry && snapEntry.chunk_hashes) || [];
      const sizeBytes = integ.size_bytes ?? cached.size_bytes;
      const rowCount = integ.row_count ?? cached.row_count;

      document.getElementById('inspContentSha').textContent = attSha || 'NONE (Unattested)';
      if (obsSha && attSha) {
        const match = obsSha.toLowerCase() === attSha.toLowerCase();
        document.getElementById('inspObservedSha').innerHTML = `${obsSha} ${match ? '<span style="color:#34d399;font-weight:700;">(&#10004; Match)</span>' : '<span style="color:#ef4444;font-weight:700;">(&#10006; DRIFT!)</span>'}`;
      } else {
        document.getElementById('inspObservedSha').textContent = obsSha || '-';
      }
      document.getElementById('inspTextSha').textContent = textSha || '-';
      document.getElementById('inspSchemaSha').textContent = schemaSha || 'N/A (Unstructured File)';
      document.getElementById('inspFpMethod').textContent = integ.fingerprint_method || cached.fingerprint_method || 'raw_bytes_sha256';
      document.getElementById('inspSizeRows').textContent = `${sizeBytes !== null && sizeBytes !== undefined ? Number(sizeBytes).toLocaleString() + ' bytes' : '-'}${rowCount !== null && rowCount !== undefined ? ' • ' + Number(rowCount).toLocaleString() + ' rows' : ''}`;
      document.getElementById('inspChunkCount').innerHTML = `<strong style="color:#38bdf8;">${Array.isArray(chunks) ? chunks.length : 0}</strong> canonical paragraph/row SHA-256 chunk digest(s)`;

      // Group 3: Provenance
      document.getElementById('inspAttestedBy').textContent = prov.attested_by || cached.attested_by || (isFound ? 'pod-engine-v0.1' : '-');
      document.getElementById('inspSourceSystem').textContent = prov.source_system || cached.source_system || (isFound ? 'tika+presidio' : '-');
      document.getElementById('inspScannerVer').textContent = prov.scanner_version || cached.scanner_version || '0.1.0';
      document.getElementById('inspDiscoveredAt').textContent = prov.discovered_at || cached.discovered_at || rec.issued_at || '-';
      const derived = prov.derived_from || cached.derived_from || [];
      document.getElementById('inspDerivedFrom').innerHTML = (Array.isArray(derived) && derived.length > 0)
        ? derived.map(d => `<code>${d.locator || d}</code>`).join(', ')
        : '<span style="color:#94a3b8;">Primary Source Object (0 upstream lineage dependencies)</span>';

      // Group 7: Lifecycle & DSSE Signature
      document.getElementById('inspLifeStatus').innerHTML = `<code>${statusStr}</code>${cached.preval_reason_detail ? ' — <span style="color:#93c5fd;">' + cached.preval_reason_detail + '</span>' : ''}`;
      document.getElementById('inspIssuedAt').textContent = life.issued_at || rec.issued_at || cached.issued_at || '-';
      const expStr = life.expires_at || rec.expires_at || cached.expires_at || (snapEntry && snapEntry.expires_at) || '-';
      const ttlStr = life.ttl_days || cached.ttl_days ? ` (TTL: ${life.ttl_days || cached.ttl_days} days)` : '';
      document.getElementById('inspExpiresAt').textContent = `${expStr}${ttlStr}`;
      document.getElementById('inspPrevRecId').textContent = life.previous_record_id || cached.previous_record_id || 'None (Initial Record Version)';

      const inSnap = Boolean((apiData && apiData.in_active_snapshot) || snapEntry);
      document.getElementById('inspSnapStatus').innerHTML = inSnap
        ? `<span style="color:#34d399;font-weight:700;">&#10004; Active in In-Memory Snapshot${apiData && apiData.snapshot_sequence ? ' #' + apiData.snapshot_sequence : ''}</span>`
        : `<span style="color:#f87171;font-weight:700;">&#10006; Not in Active Snapshot (Blocked at Gate)</span>`;

      const sigEntry = (env && Array.isArray(env.signatures) && env.signatures[0]) || null;
      document.getElementById('inspDsseKeyId').textContent = sigEntry
        ? `keyid: ${sigEntry.keyid} (Ed25519 • sig: ${String(sigEntry.sig || '').slice(0, 20)}…)`
        : (inSnap ? 'Signed in Active DSSE Snapshot Contract' : 'Unsigned');

      const fullJsonObj = {
        locator,
        in_active_snapshot: inSnap,
        prevalidator_evaluation: cached.preval_verdict ? {
          verdict: cached.preval_verdict,
          passed: cached.preval_passed,
          reason_detail: cached.preval_reason_detail,
          observed_sha256: cached.observed_sha256
        } : undefined,
        intoto_statement: (rec && rec.statement) || (Object.keys(pred).length ? { _type: "https://in-toto.io/Statement/v1", predicateType: "https://schemas.proofofdata.dev/attestation/v0.1", predicate: pred } : null),
        dsse_envelope: env,
        reviews: (apiData && apiData.reviews) || []
      };
      currentlyInspectedFullPayload = fullJsonObj;
      document.getElementById('inspRawJson').textContent = JSON.stringify(fullJsonObj, null, 2);
    }

    async function openFileInspector(locator) {
      if (!locator) return;
      currentlyInspectedLocator = locator;
      const modal = document.getElementById('fileInspectorModal');
      if (modal) modal.style.display = 'flex';

      const cached = fileInspectorCache[locator] || {};
      renderInspectorFields(locator, cached, null);

      try {
        const resp = await fetch(`/v1/admin/record-detail?locator=${encodeURIComponent(locator)}`, {
          headers: { 'X-POD-Admin-Key': ADMIN_KEY }
        });
        if (resp.ok) {
          const apiData = await resp.json();
          renderInspectorFields(locator, cached, apiData);
        }
      } catch (e) {}
    }

    function loadInspectedFileIntoPlayground() {
      if (!currentlyInspectedLocator) return;
      const cached = fileInspectorCache[currentlyInspectedLocator] || {};
      const shaAttr = cached.content_sha256 ? ` sha256="${cached.content_sha256}"` : '';
      document.getElementById('promptInput').value = `Summarize and analyze this object:\n<pod:object locator="${currentlyInspectedLocator}"${shaAttr}>Inspecting ${cached.file_name || currentlyInspectedLocator}</pod:object>`;
      closeFileInspector();
      document.getElementById('promptInput').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    async function copyInspectedJson() {
      if (!currentlyInspectedFullPayload) return;
      try {
        await navigator.clipboard.writeText(JSON.stringify(currentlyInspectedFullPayload, null, 2));
        const banner = document.getElementById('inspBanner');
        if (banner) {
          const prev = banner.innerHTML;
          banner.innerHTML = '<strong>&#10004; Copied full In-Toto v1 Attestation Statement &amp; DSSE Envelope JSON to clipboard!</strong>';
          setTimeout(() => { banner.innerHTML = prev; }, 2000);
        }
      } catch (e) {}
    }

    loadPreset('allow');
    loadLlmConfig();
    loadPcFoldersDropdown();
    // Auto-run initial directory attestation and Prevalidator scan so verifiable English counts appear immediately
    attestSelectedDirectory();
    refreshCrawlerTelemetry(true);
    setInterval(() => refreshCrawlerTelemetry(false), 650);
  </script>
</body>
</html>"""


DLP_CONNECTOR_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>G1 Docket — Multi-Cloud DLP & Microsoft Purview Connector | G1163RT Security Labs</title>
  <link rel="icon" type="image/png" href="/assets/g1-logo.png" />
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #3b82f6;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 20px 28px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
      margin-bottom: 18px;
    }
    .brand-lockup {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .brand-logo {
      width: 52px;
      height: 52px;
      border-radius: 12px;
      object-fit: contain;
      background: #ffffff;
      padding: 3px;
      box-shadow: 0 0 16px rgba(59, 130, 246, 0.35);
      border: 1px solid #374151;
    }
    h1 { margin: 0; font-size: 21px; font-weight: 700; letter-spacing: -0.01em; }
    .sub { color: var(--muted); font-size: 13px; margin-top: 4px; }
    .lab-pill {
      display: inline-block;
      background: rgba(59, 130, 246, 0.14);
      border: 1px solid rgba(59, 130, 246, 0.4);
      color: #93c5fd;
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 999px;
      margin-left: 8px;
      vertical-align: middle;
    }
    .badge {
      background: rgba(16, 185, 129, 0.15);
      color: var(--green);
      border: 1px solid rgba(16, 185, 129, 0.4);
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
      margin-bottom: 18px;
    }
    h2 { margin: 0 0 10px 0; font-size: 15px; font-weight: 600; color: #f3f4f6; }
    label { display: block; font-size: 12px; color: var(--muted); margin: 8px 0 4px; }
    select, input {
      width: 100%;
      background: #030712;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
    }
    button {
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 6px;
      padding: 9px 14px;
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
    }
    button:hover { opacity: 0.92; }
    .btn-secondary {
      background: #1f2937;
      border: 1px solid #374151;
      color: #d1d5db;
    }
    .btn-green {
      background: #059669;
      color: #ffffff;
    }
    .btn-purple {
      background: #7c3aed;
      color: #ffffff;
    }
    .btn-amber {
      background: #d97706;
      color: #ffffff;
    }
    table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    .pill { padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; display: inline-block; }
    .tier-Public { background: rgba(16,185,129,0.2); color: #34d399; }
    .tier-Internal { background: rgba(59,130,246,0.2); color: #60a5fa; }
    .tier-Confidential { background: rgba(245,158,11,0.2); color: #fbbf24; }
    .tier-Restricted { background: rgba(239,68,68,0.2); color: #f87171; }
    .stage-num {
      display: inline-block;
      background: #1e3a8a;
      color: #93c5fd;
      border: 1px solid #3b82f6;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      margin-right: 6px;
    }
    .cloud-checks {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 6px;
    }
    .cloud-checks label {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin: 0;
      background: #030712;
      border: 1px solid #1f2937;
      padding: 6px 10px;
      border-radius: 6px;
      color: #e5e7eb;
      font-size: 12px;
      cursor: pointer;
    }
    .cloud-checks input[type="checkbox"] {
      width: auto;
      margin: 0;
    }
    footer {
      margin-top: 28px;
      padding: 16px 12px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      color: var(--muted);
      font-size: 12px;
      flex-wrap: wrap;
      gap: 12px;
    }
    .footer-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      color: #e5e7eb;
      font-weight: 600;
    }
    .footer-logo {
      width: 26px;
      height: 26px;
      border-radius: 6px;
      background: #ffffff;
      padding: 2px;
      object-fit: contain;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand-lockup">
      <img src="/assets/g1-logo.png" alt="G1 Logo" class="brand-logo" />
      <div>
        <h1>G1 Docket — DLP &amp; Microsoft Purview Connectors <span class="lab-pill">by G1163RT Security Labs</span></h1>
        <div class="sub">Plugs Purview &amp; Multi-Cloud DLP directly into <code>PresidioClassifier.evaluate_findings()</code> — Labels-First Fast Lane, Multi-Cloud Catalog Pull, and Catalog Write-Back</div>
      </div>
    </div>
    <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
      <a href="/" style="background:#1e293b; color:#93c5fd; border:1px solid #3b82f6; padding:7px 13px; border-radius:8px; font-size:12px; font-weight:600; text-decoration:none;">⬅ Back to Main G1 Docket Console</a>
      <div class="badge" id="statusBadge">● <code>evaluate_findings()</code> Seam Ready</div>
    </div>
  </header>

  <!-- Connector Configuration Card -->
  <div class="card" style="border-color:#3b82f6; background:linear-gradient(180deg, rgba(59,130,246,0.08), rgba(17,24,39,0.96));">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
      <div>
        <h2 style="margin:0;">☁ Cloud DLP &amp; Microsoft Purview Connection Profile</h2>
        <div class="sub">Configure how G1 Docket connects to Microsoft Purview (Azure) or other cloud DLP catalogs. All findings funnel into <code>evaluate_findings()</code> with provenance metadata.</div>
      </div>
      <button onclick="saveDlpConfig()">💾 Save Connector Config</button>
    </div>

    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-top:10px;">
      <div>
        <label>Primary DLP / Governance Provider</label>
        <select id="dlpProvider">
          <option value="Microsoft Purview (Azure Multi-Cloud Data Map)">Microsoft Purview (Azure Multi-Cloud Data Map)</option>
          <option value="AWS Macie + Purview Multi-Cloud">AWS Macie + Purview Multi-Cloud</option>
          <option value="Google Cloud Sensitive Data Protection (SDP)">Google Cloud Sensitive Data Protection (SDP)</option>
          <option value="OpenMetadata + Purview Hybrid">OpenMetadata + Purview Hybrid</option>
        </select>
      </div>
      <div>
        <label>Authentication Mode (Zero Stored Credentials Default)</label>
        <select id="dlpAuthMode">
          <option value="azure_managed_identity">Azure Managed Identity (DefaultAzureCredential — No Stored Secrets)</option>
          <option value="entra_workload_identity">Entra ID Workload Identity Federation</option>
          <option value="aws_iam_role">AWS IAM Role Assumption (Multi-Cloud S3 Connector)</option>
          <option value="gcp_workload_identity">GCP Workload Identity Pool</option>
        </select>
      </div>
      <div>
        <label>Purview Account Name</label>
        <input id="purviewAccount" type="text" value="g1-enterprise-purview" />
      </div>
      <div>
        <label>Purview / Cloud Catalog Endpoint URL</label>
        <input id="purviewEndpoint" type="text" value="https://g1-enterprise-purview.purview.azure.com" />
      </div>
    </div>

    <label style="margin-top:12px;">Multi-Cloud Estates Scanned by Purview &amp; Consumed by G1 Docket (Stage 2):</label>
    <div class="cloud-checks">
      <label><input type="checkbox" class="cloud-src" value="SharePoint Online" checked /> SharePoint Online</label>
      <label><input type="checkbox" class="cloud-src" value="OneDrive" checked /> OneDrive for Business</label>
      <label><input type="checkbox" class="cloud-src" value="Azure SQL" checked /> Azure SQL Database</label>
      <label><input type="checkbox" class="cloud-src" value="Azure Blob" checked /> Azure Blob Storage</label>
      <label><input type="checkbox" class="cloud-src" value="AWS S3" checked /> AWS S3 (Multi-Cloud)</label>
      <label><input type="checkbox" class="cloud-src" value="GCP BigQuery" checked /> GCP BigQuery (Multi-Cloud)</label>
    </div>

    <div id="configSaveMsg" style="margin-top:8px; font-size:12px; color:#34d399; font-family:monospace;"></div>
  </div>

  <!-- STAGE 1 CARD -->
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
      <div>
        <h2><span class="stage-num">STAGE 1</span> Read the Labels Off the Files (Lightest — Zero API Calls, Zero Tenant Integration)</h2>
        <div class="sub">
          Purview's sensitivity labels (<code>MSIP_Label_&lt;GUID&gt;_Name</code>) are stamped directly into Office documents' own metadata (<code>docProps/custom.xml</code>).
          When G1 Docket opens a labeled <code>.docx</code> or <code>.xlsx</code>, it reads the label directly and maps it 1:1 to the attestation tier ladder
          (<strong>Public → Public</strong>, <strong>Internal → Internal</strong>, <strong>Confidential → Confidential</strong>, <strong>Highly Confidential / Restricted → Restricted</strong>).
        </div>
      </div>
    </div>

    <div style="display:grid; grid-template-columns: 2fr 1.2fr 1.3fr; gap:12px; align-items:end; margin-top:12px;">
      <div>
        <label>Select PC Directory to Inspect for Embedded Purview Sensitivity Labels</label>
        <select id="stage1DirSelect"></select>
      </div>
      <div>
        <button class="btn-green" style="width:100%;" onclick="runStage1Inspect()">1. Scan Files for Embedded Purview Labels</button>
      </div>
      <div style="display:flex; gap:6px;">
        <select id="stampLabelSelect" style="width:55%;">
          <option value="Highly Confidential">Highly Confidential (→ Restricted)</option>
          <option value="Confidential">Confidential (→ Confidential)</option>
          <option value="Internal">Internal (→ Internal)</option>
          <option value="Public">Public (→ Public)</option>
        </select>
        <button class="btn-secondary" style="width:45%;" onclick="stampNewPurviewDocx()">+ Stamp .docx</button>
      </div>
    </div>

    <div id="stage1Banner" style="margin-top:12px; padding:11px 14px; border-radius:8px; background:#030712; border:1px solid #1f2937; font-size:13px; font-weight:600; color:#93c5fd;">
      Loading Stage 1 embedded label scan...
    </div>

    <div style="max-height:230px; overflow:auto; margin-top:8px;">
      <table>
        <thead>
          <tr>
            <th>File Name</th>
            <th>Purview Label Found?</th>
            <th>Embedded <code>MSIP_Label</code> Name</th>
            <th>Label GUID &amp; Method</th>
            <th>Metadata Part</th>
            <th>1:1 G1 Docket Tier Mapping</th>
          </tr>
        </thead>
        <tbody id="stage1TableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- STAGE 2 CARD -->
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
      <div>
        <h2><span class="stage-num">STAGE 2</span> Pull Purview's Multi-Cloud Catalog (The Real Integration via <code>evaluate_findings()</code>)</h2>
        <div class="sub">
          Authenticates with Azure Managed Identity (zero stored credentials) and pulls classifications per asset across SharePoint, OneDrive, Azure SQL, Azure Blob, AWS S3, and GCP BigQuery.
          Each classification becomes a <code>CategoryFinding</code> fed into <code>PresidioClassifier.evaluate_findings()</code>, and G1 Docket issues a DSSE-signed attestation record on top.
        </div>
      </div>
      <button class="btn-purple" onclick="runStage2PullCatalog()">2. Pull Purview Multi-Cloud Catalog &amp; Issue Signed Records</button>
    </div>

    <div id="stage2Banner" style="margin-top:12px; padding:11px 14px; border-radius:8px; background:#030712; border:1px solid #1f2937; font-size:13px; font-weight:600; color:#c4b5fd;">
      Click "2. Pull Purview Multi-Cloud Catalog &amp; Issue Signed Records" to consume Purview's multi-cloud crawl and mint DSSE-signed records.
    </div>

    <div style="max-height:280px; overflow:auto; margin-top:8px;">
      <table>
        <thead>
          <tr>
            <th>Cloud Estate</th>
            <th>Asset Name &amp; Locator</th>
            <th>Purview Label</th>
            <th>Purview Classifications (Fed to <code>evaluate_findings</code>)</th>
            <th>G1 Docket Signed Tier</th>
            <th>Signed Record ID</th>
            <th>Expires At</th>
            <th>Write-Back State</th>
          </tr>
        </thead>
        <tbody id="stage2TableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- STAGE 3 CARD -->
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
      <div>
        <h2><span class="stage-num">STAGE 3</span> Catalog Write-Back (Heaviest, Optional — Annotate G1 Docket State Back into Purview)</h2>
        <div class="sub">
          Writes G1 Docket's cryptographic attestation state (<code>G1DocketAttestation.record_id</code>, <code>docket_tier</code>, <code>content_sha256</code>, <code>expires_at</code>, and <code>dsse_key_id</code>)
          back into Purview's Data Map catalog (<code>POST /datamap/api/atlas/v2/entity/guid/{guid}/businessmetadata</code>) so the governance team sees attestation state in the tool they already use.
        </div>
      </div>
      <button class="btn-amber" onclick="runStage3WriteBack()">3. Write Back Signed Tier &amp; Expiry to Purview Catalog</button>
    </div>

    <div id="stage3Banner" style="margin-top:12px; padding:11px 14px; border-radius:8px; background:#030712; border:1px solid #1f2937; font-size:13px; font-weight:600; color:#fcd34d;">
      Stage 3 is staged last so you can pull &amp; attest first (Stage 2) without requiring Purview Data Curator write-back permissions upfront.
    </div>

    <div style="max-height:240px; overflow:auto; margin-top:8px;">
      <table>
        <thead>
          <tr>
            <th>Purview Entity GUID</th>
            <th>Cloud Estate</th>
            <th>Asset Locator</th>
            <th>Purview Atlas API Endpoint</th>
            <th>Annotated G1 Docket Tier</th>
            <th>Annotated Record ID</th>
            <th>Annotated Expiry</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="stage3TableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- FILE / OBJECT CLASSIFICATION, OWNERSHIP & ATTESTATION INSPECTOR MODAL DRAWER -->
  <div id="fileInspectorModal" class="inspector-overlay" onclick="if(event.target === this) closeFileInspector()">
    <div class="inspector-modal">
      <div class="inspector-header">
        <div style="flex: 1; min-width: 0;">
          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <span style="font-size: 20px;">&#128269;</span>
            <span id="inspTitle" style="font-size: 18px; font-weight: 800; color: #f8fafc;">Object Attestation Inspector</span>
            <span id="inspTierBadge" class="badge badge-Public">PUBLIC</span>
            <span id="inspStatusBadge" class="badge badge-Internal">ISSUED</span>
            <span id="inspPrevalBadge" class="badge badge-PASS" style="display: none;">PASS</span>
          </div>
          <div style="margin-top: 6px; font-size: 12px; color: #93c5fd; font-family: ui-monospace, monospace; word-break: break-all;">
            Canonical Locator: <strong id="inspLocator">-</strong>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
          <button class="btn btn-green" style="padding: 6px 12px; font-size: 12px;" onclick="loadInspectedFileIntoPlayground()">&#129514; Load in Prompt Playground</button>
          <button class="btn btn-dark" style="padding: 6px 12px; font-size: 12px;" onclick="copyInspectedJson()">&#128203; Copy Signed DSSE JSON</button>
          <button class="btn" style="background: #dc2626; padding: 6px 12px; font-size: 12px;" onclick="closeFileInspector()">&#10005; Close</button>
        </div>
      </div>

      <div class="inspector-body">
        <div id="inspBanner" class="english-verdict" style="margin-bottom: 0; font-size: 13px; padding: 10px 14px;">
          Loading full 32-field POD in-toto v1 Attestation Statement &amp; DSSE signature envelope...
        </div>

        <div class="inspector-grid">
          <!-- GROUP 1 & 2: OWNERSHIP, STEWARDSHIP & ASSET IDENTITY -->
          <div class="inspector-section">
            <h3>
              <span>&#128100; Ownership, Governance &amp; Asset Identity</span>
              <span style="font-size: 10.5px; color: var(--muted);">Groups 1 &amp; 2</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Accountable Owner</div><div id="inspOwner" class="kv-val" style="color: #38bdf8; font-weight: 700;">-</div></div>
            <div class="kv-row"><div class="kv-label">Data Steward</div><div id="inspSteward" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Organizational Unit</div><div id="inspOrgUnit" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Jurisdiction</div><div id="inspJurisdiction" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Attestation Record ID</div><div class="kv-val"><code id="inspRecordId">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Object Type &amp; Env</div><div class="kv-val"><code id="inspObjTypeEnv">-</code></div></div>
          </div>

          <!-- GROUP 5: CLASSIFICATION & DETECTED SENSITIVE ENTITIES -->
          <div class="inspector-section">
            <h3>
              <span>&#128270; Classification &amp; Sensitive Entity Findings</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 5</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Classified Tier</div><div id="inspClassTier" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Confidence Score</div><div id="inspConfidence" class="kv-val" style="font-weight: 700; color: #34d399;">-</div></div>
            <div class="kv-row"><div class="kv-label">Classifier Engine</div><div class="kv-val"><code id="inspClassifierEngine">-</code></div></div>
            <div style="margin-top: 8px;">
              <div class="kv-label" style="margin-bottom: 6px;">Detected Sensitive Entity Categories (PII / PHI / PCI / Labels):</div>
              <div id="inspSensitiveCats" style="background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 8px; max-height: 115px; overflow-y: auto; font-size: 12px;">
                -
              </div>
            </div>
          </div>

          <!-- GROUP 6: AI HANDLING & ZERO-TRUST ENFORCEMENT POLICY -->
          <div class="inspector-section">
            <h3>
              <span>&#128737; AI Handling &amp; Zero-Trust Gate Policy</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 6</span>
            </h3>
            <div class="kv-row"><div class="kv-label">AI Eligibility Rule</div><div id="inspAiRule" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Minimum Clearance</div><div id="inspMinClearance" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Allowed Egress Class</div><div id="inspEgressClass" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Allow RAG Indexing</div><div id="inspAllowRag" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Allow Model Training</div><div id="inspAllowTrain" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Redaction Categories</div><div class="kv-val"><code id="inspRedactCats">-</code></div></div>
          </div>

          <!-- GROUP 4: CRYPTOGRAPHIC INTEGRITY & CHUNK DIGESTS -->
          <div class="inspector-section">
            <h3>
              <span>&#128272; Cryptographic Integrity &amp; RAG Chunk Digests</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 4</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Attested SHA-256</div><div class="kv-val"><code id="inspContentSha" style="color: #34d399;">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Observed Disk SHA-256</div><div class="kv-val"><code id="inspObservedSha">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Extracted Text SHA-256</div><div class="kv-val"><code id="inspTextSha">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Schema SHA-256</div><div class="kv-val"><code id="inspSchemaSha">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Fingerprint Method</div><div class="kv-val"><code id="inspFpMethod">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Size &amp; Row Count</div><div id="inspSizeRows" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Verified Chunk Hashes</div><div id="inspChunkCount" class="kv-val">-</div></div>
          </div>

          <!-- GROUP 3: PROVENANCE, SCANNER & OPENLINEAGE -->
          <div class="inspector-section">
            <h3>
              <span>&#129517; Provenance, Discovery &amp; OpenLineage</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 3</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Attested By Engine</div><div class="kv-val"><code id="inspAttestedBy">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Source System</div><div class="kv-val"><code id="inspSourceSystem">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Scanner Version</div><div class="kv-val"><code id="inspScannerVer">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Discovered At</div><div class="kv-val"><code id="inspDiscoveredAt">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Upstream Lineage</div><div id="inspDerivedFrom" class="kv-val">-</div></div>
          </div>

          <!-- GROUP 7: LIFECYCLE, VALIDITY & DSSE SIGNATURE -->
          <div class="inspector-section">
            <h3>
              <span>&#9201; Lifecycle, Validity &amp; Ed25519 DSSE Signature</span>
              <span style="font-size: 10.5px; color: var(--muted);">Group 7</span>
            </h3>
            <div class="kv-row"><div class="kv-label">Lifecycle Status</div><div id="inspLifeStatus" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">Issued At (UTC)</div><div class="kv-val"><code id="inspIssuedAt">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Expires At &amp; TTL</div><div class="kv-val"><code id="inspExpiresAt">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Previous Record ID</div><div class="kv-val"><code id="inspPrevRecId">-</code></div></div>
            <div class="kv-row"><div class="kv-label">Active Snapshot Status</div><div id="inspSnapStatus" class="kv-val">-</div></div>
            <div class="kv-row"><div class="kv-label">DSSE Signing Key ID</div><div class="kv-val"><code id="inspDsseKeyId" style="color: #a78bfa;">-</code></div></div>
          </div>
        </div>

        <!-- EXPANDABLE CHUNK HASHES & RAW IN-TOTO / DSSE ENVELOPE JSON -->
        <details style="background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px;">
          <summary style="cursor: pointer; font-size: 12.5px; font-weight: 700; color: #93c5fd;">
            &#128196; View Raw In-Toto v1 Attestation Statement, DSSE Signature Envelope &amp; Canonical Chunk Hashes JSON
          </summary>
          <pre id="inspRawJson" style="margin-top: 10px; max-height: 240px; overflow-y: auto; font-size: 11.5px; color: #cbd5e1;">-</pre>
        </details>
      </div>
    </div>
  </div>

  <footer>
    <div class="footer-brand">
      <img src="/assets/g1-logo.png" alt="G1 Logo" class="footer-logo" />
      <span>G1 Docket by G1163RT Security Labs</span>
    </div>
    <div>
      Multi-Cloud DLP &amp; Microsoft Purview Seam • <code>PresidioClassifier.evaluate_findings()</code> • © G1163RT Security Labs
    </div>
  </footer>

  <script>
    const ADMIN_KEY = 'pod-dev-admin-key';

    async function loadDlpConfigAndFolders() {
      const [cfgRes, dirRes] = await Promise.all([
        fetch('/v1/admin/dlp/config', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } }),
        fetch('/v1/admin/pc-folders', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } })
      ]);
      if (cfgRes.ok) {
        const cfg = await cfgRes.json();
        document.getElementById('dlpProvider').value = cfg.provider || 'Microsoft Purview (Azure Multi-Cloud Data Map)';
        document.getElementById('dlpAuthMode').value = cfg.auth_mode || 'azure_managed_identity';
        document.getElementById('purviewAccount').value = cfg.purview_account_name || 'g1-enterprise-purview';
        document.getElementById('purviewEndpoint').value = cfg.purview_endpoint || 'https://g1-enterprise-purview.purview.azure.com';
        const enabledSources = new Set(cfg.cloud_sources_enabled || []);
        document.querySelectorAll('.cloud-src').forEach(cb => {
          cb.checked = enabledSources.has(cb.value);
        });
      }
      if (dirRes.ok) {
        const dirData = await dirRes.json();
        const sel = document.getElementById('stage1DirSelect');
        sel.innerHTML = '';
        (dirData.folders || []).forEach(f => {
          const opt = document.createElement('option');
          opt.value = f.path;
          opt.textContent = `${f.label} (${f.file_count} files)`;
          sel.appendChild(opt);
        });
      }
    }

    function getSelectedCloudSources() {
      const selected = [];
      document.querySelectorAll('.cloud-src').forEach(cb => {
        if (cb.checked) selected.push(cb.value);
      });
      return selected;
    }

    async function saveDlpConfig() {
      const payload = {
        provider: document.getElementById('dlpProvider').value,
        auth_mode: document.getElementById('dlpAuthMode').value,
        purview_account_name: document.getElementById('purviewAccount').value.trim(),
        purview_endpoint: document.getElementById('purviewEndpoint').value.trim(),
        cloud_sources_enabled: getSelectedCloudSources(),
        stage1_labels_fast_lane_enabled: true,
        stage2_catalog_pull_enabled: true,
        stage3_writeback_enabled: true
      };
      const res = await fetch('/v1/admin/dlp/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      const msg = document.getElementById('configSaveMsg');
      if (res.ok) {
        msg.textContent = `✔ Saved connector profile: ${data.config.provider} (${data.config.auth_mode}) across ${data.config.cloud_sources_enabled.length} cloud source(s).`;
      } else {
        msg.textContent = `✖ Error saving config: ${data.detail || 'Unknown error'}`;
      }
    }

    async function runStage1Inspect() {
      const dirPath = document.getElementById('stage1DirSelect').value || 'C:\\Users\\chuck\\pc_demo_folder';
      const banner = document.getElementById('stage1Banner');
      banner.style.color = '#fbbf24';
      banner.textContent = `Scanning files in ${dirPath} for embedded Purview sensitivity labels (MSIP_Label)...`;
      const res = await fetch('/v1/admin/dlp/stage1-inspect-labels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({ directory_path: dirPath })
      });
      const data = await res.json();
      if (!res.ok) {
        banner.style.color = '#f87171';
        banner.textContent = `Error: ${data.detail || 'Failed Stage 1 scan'}`;
        return;
      }
      banner.style.color = '#34d399';
      banner.textContent = `✔ ${data.english_summary}`;
      const tbody = document.getElementById('stage1TableBody');
      tbody.innerHTML = '';
      (data.files || []).forEach(f => {
        const tr = document.createElement('tr');
        const tierBadge = f.mapped_docket_tier
          ? `<span class="pill tier-${f.mapped_docket_tier}">${f.mapped_docket_tier}</span>`
          : `<span style="color:#9ca3af;">Presidio Content Fallback</span>`;
        tr.innerHTML = `
          <td><code>${f.file_name}</code></td>
          <td style="color:${f.has_purview_label ? '#34d399' : '#9ca3af'}; font-weight:600;">${f.has_purview_label ? '✔ YES (Embedded)' : 'No Label'}</td>
          <td><code>${f.purview_label_name || '—'}</code></td>
          <td><span style="font-size:11px; color:#9ca3af;">${f.purview_label_guid ? f.purview_label_guid + ' (' + f.assignment_method + ')' : '—'}</span></td>
          <td><code>${f.metadata_source || '—'}</code></td>
          <td>${tierBadge}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function stampNewPurviewDocx() {
      const dirPath = document.getElementById('stage1DirSelect').value || 'C:\\Users\\chuck\\pc_demo_folder';
      const labelName = document.getElementById('stampLabelSelect').value;
      const res = await fetch('/v1/admin/dlp/stage1-stamp-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({ directory_path: dirPath, label_name: labelName })
      });
      const data = await res.json();
      if (res.ok) {
        await runStage1Inspect();
      } else {
        alert(data.detail || 'Failed to stamp sample .docx');
      }
    }

    async function runStage2PullCatalog() {
      const banner = document.getElementById('stage2Banner');
      banner.style.color = '#fbbf24';
      banner.textContent = 'Authenticating via Azure Managed Identity and pulling multi-cloud classifications into evaluate_findings()...';
      const res = await fetch('/v1/admin/dlp/stage2-pull-catalog', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({
          cloud_sources: getSelectedCloudSources(),
          enable_writeback: false
        })
      });
      const data = await res.json();
      if (!res.ok) {
        banner.style.color = '#f87171';
        banner.textContent = `Error: ${data.detail || 'Failed Stage 2 catalog pull'}`;
        return;
      }
      banner.style.color = '#34d399';
      banner.textContent = `✔ ${data.english_summary}`;
      const tbody = document.getElementById('stage2TableBody');
      tbody.innerHTML = '';
      (data.attested_assets || []).forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${a.cloud_source}</strong></td>
          <td><div><strong>${a.asset_name}</strong></div><code style="font-size:10px; color:#9ca3af;">${a.locator}</code></td>
          <td><code>${a.purview_label || 'None'}</code></td>
          <td><code style="font-size:11px; color:#93c5fd;">${(a.purview_classifications || []).join(', ')}</code></td>
          <td><span class="pill tier-${a.docket_tier}">${a.docket_tier}</span></td>
          <td><code style="font-size:11px;">${a.record_id}</code></td>
          <td style="font-size:11px; color:#9ca3af;">${a.expires_at ? a.expires_at.slice(0, 10) : '—'}</td>
          <td style="font-size:11px; color:#fbbf24;">${a.writeback ? '✔ Annotated' : 'Staged for Stage 3'}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function runStage3WriteBack() {
      const banner = document.getElementById('stage3Banner');
      banner.style.color = '#fbbf24';
      banner.textContent = 'Writing G1 Docket signed attestation tier, record_id, and expiry back to Purview Data Map businessmetadata...';
      const res = await fetch('/v1/admin/dlp/stage3-writeback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({})
      });
      const data = await res.json();
      if (!res.ok) {
        banner.style.color = '#f87171';
        banner.textContent = `Error: ${data.detail || 'Failed Stage 3 write-back'}`;
        return;
      }
      banner.style.color = '#34d399';
      banner.textContent = `✔ ${data.english_summary}`;
      const tbody = document.getElementById('stage3TableBody');
      tbody.innerHTML = '';
      (data.writeback_results || []).forEach(w => {
        const meta = (w.business_metadata_payload && w.business_metadata_payload.G1DocketAttestation) || {};
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code>${w.purview_guid}</code></td>
          <td><strong>${w.cloud_source}</strong></td>
          <td><code style="font-size:11px;">${w.locator}</code></td>
          <td><code style="font-size:10px; color:#93c5fd;">${w.purview_api_endpoint}</code></td>
          <td><span class="pill tier-${meta.docket_tier}">${meta.docket_tier}</span></td>
          <td><code style="font-size:11px;">${meta.record_id}</code></td>
          <td style="font-size:11px; color:#9ca3af;">${meta.expires_at ? meta.expires_at.slice(0, 10) : '—'}</td>
          <td style="color:#34d399; font-weight:600;">✔ ${w.writeback_status}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    (async () => {
      await loadDlpConfigAndFolders();
      await runStage1Inspect();
      await runStage2PullCatalog();
    })();
  </script>
</body>
</html>"""


def create_prevalidator_app(
    enforcer: PrevalidatorEnforcer | None = None,
    upstream_gateway_url: str | None = None,
    snapshot_file: str | Path | None = None,
    engine_service_url: str | None = None,
) -> FastAPI:
    """Create the Prevalidator proxy application."""
    app = FastAPI(title="G1 Docket by G1163RT Security Labs — AI Gateway Prevalidator", version="0.1.0")
    logo_path = Path(__file__).resolve().parent / "g1_logo.png"

    if enforcer is None:
        pub_key_dir = Path(os.environ.get("POD_PUBLIC_KEY_DIR") or os.environ.get("POD_KEY_DIR", "./.pod_keys"))
        keyring = Keyring(public_key_dir=pub_key_dir, verification_only=True)
        store = InMemorySnapshotStore(keyring)
        snap_path = Path(snapshot_file or os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json"))
        if snap_path.exists():
            try:
                store.load_from_file(snap_path)
            except Exception:
                # If a stale snapshot from an earlier boot exists on disk, start cleanly (fail-closed)
                # until SnapshotPublisher/Engine pushes a fresh signed snapshot.
                pass
        mode = os.environ.get("POD_PREVALIDATOR_MODE", "enforce")
        enforcer = PrevalidatorEnforcer(snapshot_store=store, mode=mode)

    upstream_url = (upstream_gateway_url or os.environ.get("POD_UPSTREAM_GATEWAY_URL", "mock://local")).rstrip("/")
    engine_url = (engine_service_url or os.environ.get("POD_ENGINE_SERVICE_URL", "http://engine:8083")).rstrip("/")
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    control_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")
    llm_config_file = Path(os.environ.get("POD_LLM_CONFIG_FILE", "./llm_provider_config.json"))

    llm_config: dict[str, Any] = {
        "provider_name": "Built-in G1 Gateway",
        "protocol": "openai",
        "base_url": upstream_url,
        "default_model": "local-model",
        "egress_class": "local_only",
        "api_key": os.environ.get("POD_UPSTREAM_API_KEY", ""),
    }
    if llm_config_file.exists():
        try:
            saved_cfg = json.loads(llm_config_file.read_text(encoding="utf-8"))
            if isinstance(saved_cfg, dict) and saved_cfg.get("base_url"):
                llm_config.update(saved_cfg)
                if llm_config.get("default_model") and llm_config.get("egress_class"):
                    enforcer.route_egress_map[llm_config["default_model"]] = llm_config["egress_class"]
        except Exception:
            pass

    def _public_llm_config() -> dict[str, Any]:
        raw_key = llm_config.get("api_key") or ""
        masked = f"{raw_key[:5]}...{raw_key[-4:]}" if len(raw_key) > 9 else ("****" if raw_key else "")
        return {
            "provider_name": llm_config["provider_name"],
            "protocol": llm_config["protocol"],
            "base_url": llm_config["base_url"],
            "default_model": llm_config["default_model"],
            "egress_class": llm_config["egress_class"],
            "has_api_key": bool(raw_key),
            "api_key_masked": masked,
            "route_egress_map": enforcer.route_egress_map,
        }

    @app.get("/", response_class=HTMLResponse)
    def root_console() -> str:
        return DASHBOARD_HTML

    @app.get("/dlp", response_class=HTMLResponse)
    def dlp_connector_console() -> str:
        return DLP_CONNECTOR_HTML

    @app.get("/v1/admin/dlp/config")
    async def proxy_dlp_get_config(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/dlp/config")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/config")
    async def proxy_dlp_save_config(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/config", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage1-inspect-labels")
    async def proxy_dlp_stage1_inspect(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage1-inspect-labels", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage1-stamp-sample")
    async def proxy_dlp_stage1_stamp(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage1-stamp-sample", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage2-pull-catalog")
    async def proxy_dlp_stage2_pull(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage2-pull-catalog", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/dlp/stage3-writeback")
    async def proxy_dlp_stage3_writeback(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{engine_url}/v1/dlp/stage3-writeback", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/assets/g1-logo.png", include_in_schema=False)
    def serve_g1_logo() -> FileResponse:
        return FileResponse(logo_path, media_type="image/png")

    @app.get("/favicon.ico", include_in_schema=False)
    def serve_favicon() -> FileResponse:
        return FileResponse(logo_path, media_type="image/png")

    @app.get("/v1/admin/snapshot-view")
    def get_snapshot_view(x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        return {"snapshot": enforcer.snapshot_store.get_active_snapshot()}

    @app.get("/v1/admin/browse-dir")
    async def proxy_browse_dir(
        path: str = Query(default="D:\\attestation"),
        x_pod_admin_key: str | None = Header(default=None),
    ) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/browse-dir", params={"path": path})
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/pc-folders")
    async def proxy_pc_folders(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/pc-folders")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/datastores")
    async def proxy_get_datastores(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/datastores")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/datastores")
    async def proxy_register_datastore(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{engine_url}/v1/datastores", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/events/storage")
    async def proxy_storage_event(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{engine_url}/v1/events/storage", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/crawler/status")
    async def proxy_crawler_status(x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{engine_url}/v1/crawler/status")
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/admin/crawler/control")
    async def proxy_crawler_control(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{engine_url}/v1/crawler/control", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.get("/v1/admin/record-detail")
    async def proxy_record_detail(
        locator: str = Query(..., description="Canonical object locator URI"),
        x_pod_admin_key: str | None = Header(default=None),
    ) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        snap = enforcer.snapshot_store.get_active_snapshot()
        snap_entries = snap.get("entries", {}) if snap else {}
        snap_entry = snap_entries.get(locator)
        data: dict[str, Any] = {
            "found": False,
            "locator": locator,
            "in_active_snapshot": snap_entry is not None,
            "snapshot_id": snap.get("snapshot_id") if snap else None,
            "snapshot_sequence": snap.get("sequence_number") if snap else None,
            "snapshot_entry": snap_entry,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(f"{engine_url}/v1/record-detail", params={"locator": locator})
                if r.status_code == 200:
                    eng_data = r.json()
                    data.update(eng_data)
        except Exception as exc:
            data["engine_lookup_warning"] = str(exc)
        return JSONResponse(status_code=200, content=data)

    @app.post("/v1/admin/attest-directory")
    async def proxy_attest_directory(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                r = await client.post(f"{engine_url}/v1/attest-directory", json=body)
                try:
                    payload = r.json()
                except Exception:
                    payload = {"detail": r.text or f"Engine returned HTTP {r.status_code}"}
                return JSONResponse(status_code=r.status_code, content=payload)
        except Exception as exc:
            return JSONResponse(status_code=502, content={"detail": f"Attestation Engine request failed or timed out: {exc}"})

    @app.post("/v1/admin/add-unattested-file")
    async def proxy_add_unattested(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{engine_url}/v1/demo-folder/add-unattested", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

    @app.post("/v1/prevalidate-directory")
    async def prevalidate_directory(request: Request) -> dict[str, Any]:
        """Scan every file in a directory (by PC path or browser folder picker upload) against the in-memory signed snapshot."""
        t_wall_start_ns = time.perf_counter_ns()
        body = await request.json()
        caller_key = body.get("caller_key", "pod-key-confidential")
        model = body.get("model", "local-model")
        uploaded_files = body.get("files")
        directory_path = body.get("directory_path")

        snap = enforcer.snapshot_store.get_active_snapshot()
        entries = snap.get("entries", {}) if snap else {}

        file_candidates: list[tuple[str, str, str]] = []  # (file_name, locator, observed_sha256)
        dir_label = directory_path or "picked-folder"
        if uploaded_files:
            folder_slug = "picked-folder"
            for item in uploaded_files:
                rel = item["relative_path"].replace("\\", "/").lstrip("/")
                parts = rel.split("/")
                if len(parts) > 1:
                    folder_slug = parts[0]
                    rel_inside = "/".join(parts[1:])
                else:
                    rel_inside = parts[0]
                raw_bytes = base64.b64decode(item["content_b64"])
                sha = compute_bytes_sha256_hex(raw_bytes)
                loc = f"file://pc-dir/{folder_slug}/{rel_inside}"
                file_candidates.append((rel_inside, loc, sha))
        elif directory_path and is_enterprise_store_uri(directory_path):
            async with httpx.AsyncClient(timeout=20.0) as client:
                r_objs = await client.get(f"{engine_url}/v1/datastores/objects", params={"uri": directory_path})
                if r_objs.status_code != 200:
                    raise HTTPException(status_code=r_objs.status_code, detail=r_objs.text)
                obj_data = r_objs.json()
                dir_label = obj_data.get("store_label") or directory_path
                for item in obj_data.get("objects", []):
                    file_candidates.append((item["file_name"], item["locator"], item["observed_sha256"]))
        elif directory_path:
            max_files = int(body.get("max_files", 120))
            include_code_dirs = bool(body.get("include_code_dirs", False))
            try:
                target_dir, locator_base = resolve_pc_directory_path(directory_path)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

            for p, rel_inside in iter_scannable_files_unbounded(target_dir, include_code_dirs=include_code_dirs):
                try:
                    sha = compute_file_sha256(p)
                    loc = f"{locator_base.rstrip('/')}/{rel_inside}"
                    file_candidates.append((rel_inside, loc, sha))
                    if max_files > 0 and len(file_candidates) >= max_files:
                        break
                except OSError:
                    continue
        else:
            raise HTTPException(status_code=400, detail="Provide either directory_path or files.")

        passed_count = 0
        allow_count = 0
        strip_count = 0
        failed_count = 0
        unattested_count = 0
        hash_drift_count = 0
        policy_denied_count = 0
        file_results: list[dict[str, Any]] = []
        in_memory_enforcer_ns = 0

        for file_name, loc, obs_sha in file_candidates:
            snap_entry = entries.get(loc)
            sim_payload = {
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": f'<pod:object locator="{loc}" sha256="{obs_sha}">File content check</pod:object>',
                    }
                ],
            }
            t_eval_ns = time.perf_counter_ns()
            try:
                outcome = enforcer.evaluate_request(
                    payload=sim_payload,
                    headers={"X-POD-Caller-Key": caller_key},
                    verify_inline_text=False,
                )
            finally:
                in_memory_enforcer_ns += max(100, time.perf_counter_ns() - t_eval_ns)
            reasons = outcome.audit_entry.reason_codes
            is_clean_pass = len(reasons) == 0 and outcome.allowed_to_forward
            is_observe_mode = enforcer.mode == "observe"
            is_pass = is_clean_pass or (is_observe_mode and outcome.allowed_to_forward)

            if not snap_entry:
                att_state = "UNATTESTED"
                tier = "NONE"
                unattested_count += 1
                if is_observe_mode:
                    reason_detail = "OBSERVE MODE (FORWARDED + LOGGED) — Unattested file (would block in Enforce Mode)"
                else:
                    reason_detail = "UNATTESTED — No signed record in snapshot"
            elif snap_entry["content_sha256"].lower() != obs_sha.lower():
                att_state = "HASH_DRIFT"
                tier = snap_entry["tier"]
                unattested_count += 1
                hash_drift_count += 1
                if is_observe_mode:
                    reason_detail = "OBSERVE MODE (FORWARDED + LOGGED) — File SHA-256 modified (would block in Enforce Mode)"
                else:
                    reason_detail = "UNATTESTED — File content SHA-256 modified since attestation"
            else:
                att_state = f"ATTESTED ({snap_entry['status'].upper()})"
                tier = snap_entry["tier"]
                if is_clean_pass:
                    if outcome.audit_entry.decision == "strip":
                        strip_count += 1
                        reason_detail = "PASSED (STRIP) — Confidential content stripped per policy"
                    else:
                        allow_count += 1
                        reason_detail = "PASSED (ALLOW) — Hash & policy verified"
                else:
                    policy_denied_count += 1
                    if is_observe_mode:
                        reason_detail = f"OBSERVE MODE (FORWARDED + LOGGED) — Would block in Enforce Mode: {', '.join(reasons)}"
                    else:
                        reason_detail = f"BLOCKED — {', '.join(reasons)}"

            if is_clean_pass:
                passed_count += 1
                verdict = "PASS (STRIP)" if outcome.audit_entry.decision == "strip" else "PASS (ALLOW)"
            elif is_observe_mode and outcome.allowed_to_forward:
                passed_count += 1
                verdict = "OBSERVED (WOULD BLOCK)"
            else:
                failed_count += 1
                verdict = "FAILED / BLOCKED"

            file_results.append(
                {
                    "file_name": file_name,
                    "locator": loc,
                    "observed_sha256": obs_sha,
                    "attestation_state": att_state,
                    "tier": tier,
                    "passed": is_pass,
                    "verdict": verdict,
                    "reason_codes": reasons,
                    "reason_detail": reason_detail,
                }
            )

        total_count = len(file_candidates)
        total_wall_ms = round((time.perf_counter_ns() - t_wall_start_ns) / 1_000_000.0, 2)
        enforcer_ms = round(in_memory_enforcer_ns / 1_000_000.0, 3)
        avg_file_us = round((in_memory_enforcer_ns / 1_000.0) / max(1, total_count), 1)
        files_per_sec = round((total_count / max(0.0001, in_memory_enforcer_ns / 1_000_000_000.0)), 1)
        enforcer.last_directory_scan_metrics = {
            "total_files": total_count,
            "total_wall_ms": total_wall_ms,
            "in_memory_enforcer_ms": enforcer_ms,
            "avg_per_file_us": avg_file_us,
            "files_per_sec": files_per_sec,
        }

        pure_unattested = unattested_count - hash_drift_count
        mode_tag = "OBSERVE MODE (Audit-Only — Violations Forwarded & Logged)" if enforcer.mode == "observe" else "ENFORCE MODE (Active Blocking)"
        english_summary = (
            f"[{mode_tag}] Prevalidator scanned {total_count} total file(s) in '{dir_label}' in {enforcer_ms} ms in-memory ({avg_file_us} µs/file; {total_wall_ms} ms incl. disk SHA-256): "
            f"{passed_count} of {total_count} file(s) PASSED/FORWARDED ({allow_count} Clean Allowed, {strip_count} Stripped) and "
            f"{failed_count} of {total_count} file(s) BLOCKED "
            f"({pure_unattested} Unattested file(s) with no signed record, "
            f"{hash_drift_count} Modified/Hash-drift file(s), "
            f"{policy_denied_count} Policy/Clearance violation(s))."
        )

        return {
            "directory": dir_label,
            "total_files": total_count,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "unattested_count": unattested_count,
            "english_summary": english_summary,
            "caller_key": caller_key,
            "model": model,
            "latency": enforcer.get_latency_telemetry(),
            "files": file_results,
        }

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        snap = enforcer.snapshot_store.get_active_snapshot()
        return {
            "status": "ok" if snap is not None else "stale_or_missing_snapshot",
            "mode": enforcer.mode,
            "snapshot_sequence": snap["sequence_number"] if snap else None,
            "latency": enforcer.get_latency_telemetry(),
        }

    @app.post("/v1/admin/latency-benchmark")
    async def run_latency_benchmark_endpoint(
        request: Request,
        x_pod_admin_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        iterations = min(500, max(10, int(body.get("iterations", 100))))
        prompts = [
            (
                "gpt-4o",
                "pod-key-public",
                'Summarize doc:\n<pod:object locator="file://estate/fileshare/product_overview_public.md">Open Source AI Architecture Overview</pod:object>',
            ),
            (
                "local-model",
                "pod-key-confidential",
                'HR policy guidance:\n<pod:object locator="file://estate/fileshare/dept_compensation_confidential.xlsx">diana.prince@example.org | salary: $145,000</pod:object>',
            ),
            (
                "gpt-4o",
                "pod-key-restricted",
                'Analyze intake:\n<pod:object locator="file://estate/fileshare/clinical_intake_restricted.txt">Patient SSN: 412-58-9021, MRN-8839201</pod:object>',
            ),
            (
                "gpt-4o",
                "pod-key-public",
                '<pod:object locator="file://estate/fileshare/unverified_notes_ambiguous.txt">AMBIGUOUS_REF_9042</pod:object>',
            ),
        ]
        t0_ns = time.perf_counter_ns()
        for idx in range(iterations):
            model_id, caller_k, content = prompts[idx % len(prompts)]
            enforcer.evaluate_request(
                payload={"model": model_id, "messages": [{"role": "user", "content": content}]},
                headers={"X-POD-Caller-Key": caller_k},
            )
        wall_ms = round((time.perf_counter_ns() - t0_ns) / 1_000_000.0, 3)
        avg_us = round(((time.perf_counter_ns() - t0_ns) / 1_000.0) / iterations, 2)
        return {
            "iterations": iterations,
            "benchmark_wall_ms": wall_ms,
            "avg_eval_us": avg_us,
            "latency": enforcer.get_latency_telemetry(),
        }

    @app.get("/v1/admin/llm-config")
    def get_llm_config(x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        return _public_llm_config()

    @app.post("/v1/admin/llm-config")
    async def update_llm_config(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        provider_name = (body.get("provider_name") or "Custom LLM Provider").strip()
        protocol = (body.get("protocol") or "openai").strip().lower()
        base_url = (body.get("base_url") or "").strip().rstrip("/")
        default_model = (body.get("default_model") or "local-model").strip()
        egress_class = (body.get("egress_class") or "local_only").strip()
        new_api_key = body.get("api_key")

        if not base_url:
            raise HTTPException(status_code=400, detail="base_url is required")
        if egress_class not in ("local_only", "private_cloud", "public_api"):
            raise HTTPException(status_code=400, detail="egress_class must be local_only, private_cloud, or public_api")

        llm_config["provider_name"] = provider_name
        llm_config["protocol"] = protocol
        llm_config["base_url"] = base_url
        llm_config["default_model"] = default_model
        llm_config["egress_class"] = egress_class
        if new_api_key is not None and str(new_api_key).strip() != "":
            llm_config["api_key"] = str(new_api_key).strip()

        enforcer.route_egress_map[default_model] = egress_class
        try:
            llm_config_file.parent.mkdir(parents=True, exist_ok=True)
            llm_config_file.write_text(json.dumps(llm_config, indent=2), encoding="utf-8")
        except Exception:
            pass

        return _public_llm_config()

    @app.post("/v1/admin/llm-config/test")
    async def test_llm_config(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        base_url = (body.get("base_url") or llm_config["base_url"]).strip().rstrip("/")
        egress_class = (body.get("egress_class") or llm_config["egress_class"]).strip()
        api_key = (body.get("api_key") or llm_config.get("api_key") or "").strip()

        if base_url.startswith("mock://"):
            return {
                "reachable": True,
                "base_url": base_url,
                "status_code": 200,
                "latency_ms": 0.2,
                "discovered_models": ["local-model", "vpc-model", "gpt-4o"],
            }

        req_headers: dict[str, str] = {}
        if api_key:
            req_headers["Authorization"] = f"Bearer {api_key}"
            req_headers["x-api-key"] = api_key
            req_headers["anthropic-version"] = "2023-06-01"

        t0 = time.perf_counter()
        discovered_models: list[str] = []
        status_code = 0
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                # Probe /v1/models first, then /api/tags (Ollama), then /healthz
                for probe_path in ("/v1/models", "/models", "/api/tags", "/healthz"):
                    try:
                        r = await client.get(f"{base_url}{probe_path}", headers=req_headers)
                        status_code = r.status_code
                        if r.status_code < 500:
                            try:
                                j = r.json()
                                if isinstance(j, dict):
                                    if isinstance(j.get("data"), list):
                                        discovered_models = [str(m.get("id")) for m in j["data"] if isinstance(m, dict) and m.get("id")]
                                    elif isinstance(j.get("models"), list):
                                        discovered_models = [str(m.get("name") or m.get("id")) for m in j["models"] if isinstance(m, dict)]
                            except Exception:
                                pass
                            break
                    except Exception:
                        continue
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if status_code == 0:
                return {"reachable": False, "base_url": base_url, "error": f"Could not connect to {base_url}"}
            for m_id in discovered_models:
                if egress_class in ("local_only", "private_cloud", "public_api"):
                    enforcer.route_egress_map[m_id] = egress_class
            return {
                "reachable": True,
                "base_url": base_url,
                "status_code": status_code,
                "latency_ms": latency_ms,
                "discovered_models": discovered_models,
            }
        except Exception as exc:
            return {"reachable": False, "base_url": base_url, "error": str(exc)}

    @app.post("/v1/chat/completions")
    async def openai_chat_completions(request: Request) -> Any:
        payload = await request.json()
        headers = dict(request.headers)
        outcome = enforcer.evaluate_request(payload=payload, headers=headers)

        if not outcome.allowed_to_forward:
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=outcome.client_denial_body)

        clean_payload = outcome.transformed_payload
        model = clean_payload.get("model", llm_config.get("default_model", "gpt-4o"))
        is_stream = bool(clean_payload.get("stream", False))
        active_base_url = llm_config["base_url"]

        if active_base_url.startswith("mock://"):
            user_text = _extract_last_user_text(clean_payload)
            if is_stream:
                return StreamingResponse(_mock_openai_sse_stream(model, user_text), media_type="text/event-stream")
            return {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"[Gateway Ack ({model})]: {user_text}",
                        },
                        "finish_reason": "stop",
                    }
                ],
            }

        forward_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "x-pod-locators", "x-pod-caller-key", "x-pod-caller-token")
        }
        if llm_config.get("api_key") and "authorization" not in {k.lower() for k in forward_headers}:
            forward_headers["Authorization"] = f"Bearer {llm_config['api_key']}"

        target_endpoint = f"{active_base_url}/chat/completions" if active_base_url.endswith("/v1") or active_base_url.endswith("/openai") else f"{active_base_url}/v1/chat/completions"
        if is_stream:
            client = httpx.AsyncClient(timeout=60.0)
            req = client.build_request("POST", target_endpoint, json=clean_payload, headers=forward_headers)
            resp = await client.send(req, stream=True)

            async def stream_passthrough() -> AsyncIterator[bytes]:
                try:
                    async for chunk in resp.aiter_raw():
                        yield chunk
                finally:
                    await resp.aclose()
                    await client.aclose()

            return StreamingResponse(stream_passthrough(), status_code=resp.status_code, media_type="text/event-stream")

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(target_endpoint, json=clean_payload, headers=forward_headers)
            return JSONResponse(status_code=resp.status_code, content=resp.json())

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Any:
        payload = await request.json()
        headers = dict(request.headers)
        outcome = enforcer.evaluate_request(payload=payload, headers=headers)

        if not outcome.allowed_to_forward:
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=outcome.client_denial_body)

        clean_payload = outcome.transformed_payload
        model = clean_payload.get("model", llm_config.get("default_model", "claude-3-5-sonnet"))
        is_stream = bool(clean_payload.get("stream", False))
        active_base_url = llm_config["base_url"]

        if active_base_url.startswith("mock://"):
            user_text = _extract_last_user_text(clean_payload)
            if is_stream:
                return StreamingResponse(_mock_anthropic_sse_stream(model, user_text), media_type="text/event-stream")
            return {
                "id": f"msg_{uuid.uuid4().hex[:12]}",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [
                    {
                        "type": "text",
                        "text": f"[Anthropic Gateway Ack ({model})]: {user_text}",
                    }
                ],
                "stop_reason": "end_turn",
            }

        forward_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "x-pod-locators", "x-pod-caller-key", "x-pod-caller-token")
        }
        if llm_config.get("api_key"):
            lower_keys = {k.lower() for k in forward_headers}
            if "x-api-key" not in lower_keys:
                forward_headers["x-api-key"] = llm_config["api_key"]
            if "anthropic-version" not in lower_keys:
                forward_headers["anthropic-version"] = "2023-06-01"

        target_endpoint = f"{active_base_url}/messages" if active_base_url.endswith("/v1") else f"{active_base_url}/v1/messages"
        if is_stream:
            client = httpx.AsyncClient(timeout=60.0)
            req = client.build_request("POST", target_endpoint, json=clean_payload, headers=forward_headers)
            resp = await client.send(req, stream=True)

            async def stream_passthrough() -> AsyncIterator[bytes]:
                try:
                    async for chunk in resp.aiter_raw():
                        yield chunk
                finally:
                    await resp.aclose()
                    await client.aclose()

            return StreamingResponse(stream_passthrough(), status_code=resp.status_code, media_type="text/event-stream")

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(target_endpoint, json=clean_payload, headers=forward_headers)
            return JSONResponse(status_code=resp.status_code, content=resp.json())

    @app.get("/v1/admin/audit-log")
    def get_audit_log(x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        return {"entries": [e.to_dict() for e in enforcer.audit_log]}

    @app.post("/v1/admin/mode")
    async def set_mode(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, str]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        new_mode = body.get("mode")
        if new_mode not in ("enforce", "observe"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="mode must be 'enforce' or 'observe'")
        enforcer.mode = new_mode
        return {"mode": enforcer.mode}

    @app.post("/v1/admin/reload-snapshot")
    async def reload_snapshot(
        request: Request,
        x_pod_admin_key: str | None = Header(default=None),
        x_pod_control_token: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        bearer = None
        if authorization and authorization.lower().startswith("bearer "):
            bearer = authorization[7:].strip()
        valid_tokens = {t for t in (admin_key, control_token) if t}
        if not (
            (x_pod_admin_key and x_pod_admin_key in valid_tokens)
            or (x_pod_control_token and x_pod_control_token in valid_tokens)
            or (bearer and bearer in valid_tokens)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized control-plane request: valid X-POD-Control-Token or Bearer token required.",
            )
        body = await request.json()
        if "envelope" in body:
            pred = enforcer.snapshot_store.load_from_envelope(body["envelope"])
        else:
            path = body.get("path") or os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json")
            pred = enforcer.snapshot_store.load_from_file(path)
        return {"loaded": True, "snapshot_id": pred["snapshot_id"], "sequence_number": pred["sequence_number"]}

    return app
