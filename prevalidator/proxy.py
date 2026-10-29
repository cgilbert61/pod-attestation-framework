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
    resolve_pc_directory_path,
)
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
  <title>G1 Docket by G1183RT Security Labs | Cryptographic Proof Of Data &amp; AI Prevalidator</title>
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
  </style>
</head>
<body>
  <header>
    <div class="brand-lockup">
      <img src="/assets/g1-logo.png" alt="G1 Logo" class="brand-logo" />
      <div>
        <h1>
          <span>G1 Docket</span>
          <span class="brand-lab-tag">by G1183RT Security Labs</span>
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
      <button class="btn" style="background: #2563eb;" onclick="toggleLlmConfig()">&#9881; LLM Provider Config</button>
      <button class="btn btn-dark" onclick="toggleMode()">Toggle Enforce / Observe Mode</button>
      <a href="/docs" target="_blank">Prevalidator API</a>
      <a href="http://localhost:18083/docs" target="_blank">Engine API (:18083)</a>
      <a href="http://localhost:18080/docs" target="_blank">Registry API (:18080)</a>
      <a href="http://localhost:18081/docs" target="_blank">Snapshot API (:18081)</a>
    </div>
  </header>

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

  <!-- TOP WORKFLOW: PC DIRECTORY SELECTION + ATTESTATION + PREVALIDATOR DIRECTORY SCAN -->
  <div class="card" style="border-color: #3b82f6;">
    <h2>
      <span>Point System at Any Directory on Your PC — Attest &amp; Prevalidate Files</span>
      <span id="folderSourceBadge" class="badge badge-Internal">Direct PC Disk Path</span>
    </h2>

    <div style="display: grid; grid-template-columns: 1.4fr 1fr auto; gap: 14px; align-items: end; margin-bottom: 12px;">
      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>Select Drive or Directory on Your PC</strong> (Entire Drive <code>C:\</code>, <code>D:\</code>, or any Directory):
        </label>
        <select id="pcFolderSelect" style="margin-bottom: 0; font-size: 14px; font-weight: 600;" onchange="selectPresetFolder()">
          <option value="C:\Users\chuck\pc_demo_folder">📁 C:\Users\chuck\pc_demo_folder — Sample Disparate Files</option>
          <option value="C:\">🖴 C:\ — Entire C: Drive (Recursive Data Scan)</option>
          <option value="D:\">🖴 D:\ — Entire D: Drive (Recursive Data Scan)</option>
        </select>
        <input type="hidden" id="pcPathInput" value="C:\Users\chuck\pc_demo_folder" />
      </div>

      <div>
        <label style="font-size: 12px; color: var(--muted); display: block; margin-bottom: 4px;">
          <strong>Drill Into Subdirectory</strong> (Select subfolder inside current selection):
        </label>
        <select id="subDirSelect" style="margin-bottom: 0; font-size: 13px;" onchange="selectSubdirectory()">
          <option value="">-- Current Selected Drive / Directory --</option>
        </select>
      </div>

      <div style="display: flex; gap: 8px;">
        <input type="file" id="winFolderPicker" webkitdirectory directory multiple style="display: none;" onchange="onWinFolderPicked(event)" />
        <button class="btn" style="white-space: nowrap;" onclick="document.getElementById('winFolderPicker').click()">📂 Or Pick via Windows Explorer</button>
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

    <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap; padding-top: 10px; border-top: 1px solid var(--border);">
      <button class="btn btn-green" onclick="attestSelectedDirectory()">1. Run Attestation on Directory (Engine)</button>
      <button class="btn btn-amber" onclick="dropUnattestedFile()">+ Add Unattested File to This Directory</button>
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
        <button class="btn" onclick="prevalidateSelectedDirectory()">2. Run Prevalidator Scan on Directory</button>
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
            <th>File Name</th>
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
            <th>File Name</th>
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
              <th>Locator</th>
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

  <footer>
    <div class="footer-brand">
      <img src="/assets/g1-logo.png" alt="G1 Logo" class="footer-logo" />
      <span><strong>G1 Docket</strong> by <strong>G1183RT Security Labs</strong> &bull; G1163RT Security Labs</span>
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

    function clearPickedFiles() {
      browserPickedFiles = null;
      document.getElementById('folderSourceBadge').textContent = 'Direct PC Disk Path';
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
      await loadSubdirectoriesIntoSelect(val);
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

    async function attestSelectedDirectory() {
      document.getElementById('attestStatusText').textContent = 'Scanning & signing files...';
      const body = browserPickedFiles
        ? { files: browserPickedFiles }
        : { directory_path: document.getElementById('pcPathInput').value };

      const resp = await fetch('/v1/admin/attest-directory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify(body)
      });
      const data = await resp.json();
      if (!resp.ok) {
        document.getElementById('attestStatusText').textContent = 'Error: ' + (data.detail || resp.status);
        document.getElementById('attestEnglishBanner').textContent = 'Error: ' + (data.detail || resp.status);
        return;
      }
      document.getElementById('attestStatusText').textContent = `Attested ${data.attested_active_count} of ${data.total_files_found} file(s)`;
      document.getElementById('attestEnglishBanner').innerHTML = `<strong>Verifiable Attestation Count:</strong> ${data.english_summary}`;
      document.getElementById('attTotal').textContent = data.total_files_found;
      document.getElementById('attActive').textContent = data.attested_active_count;
      document.getElementById('attHeld').textContent = data.held_in_review_count;

      const tbody = document.querySelector('#attestedFilesTable tbody');
      tbody.innerHTML = '';
      (data.files || []).forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><strong>${f.file_name}</strong></td>
          <td><code>${f.object_type}</code></td>
          <td><span class="badge badge-${f.tier}">${f.tier}</span></td>
          <td><code>${f.ai_eligibility} / ${f.egress_class}</code></td>
          <td><code>${(f.content_sha256 || '').slice(0, 12)}…</code></td>`;
        tbody.appendChild(tr);
      });
      await prevalidateSelectedDirectory();
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
      const body = browserPickedFiles
        ? { files: browserPickedFiles, caller_key: callerKey, model }
        : { directory_path: document.getElementById('pcPathInput').value, caller_key: callerKey, model };

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
        const tr = document.createElement('tr');
        const verdictBadge = f.passed ? 'badge-PASS' : 'badge-FAIL';
        const tierBadge = f.tier && f.tier !== 'NONE' ? `badge-${f.tier}` : 'badge-FAIL';
        tr.innerHTML = `<td><strong>${f.file_name}</strong></td>
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
      const badge = document.getElementById('modeBadge');
      badge.textContent = currentMode.toUpperCase() + ' MODE';
      badge.className = 'badge ' + (currentMode === 'enforce' ? 'badge-Public' : 'badge-Confidential');

      const snapResp = await (await fetch('/v1/admin/snapshot-view', { headers: { 'X-POD-Admin-Key': ADMIN_KEY } })).json();
      if (snapResp.snapshot) {
        const s = snapResp.snapshot;
        document.getElementById('snapMeta').textContent = `Snapshot ID: ${s.snapshot_id} | Sequence: #${s.sequence_number} | Total Entries: ${Object.keys(s.entries).length} | Expires: ${s.expires_at}`;
        const tbody = document.querySelector('#entriesTable tbody');
        tbody.innerHTML = '';
        Object.values(s.entries).forEach(e => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td><code>${e.locator}</code></td>
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
        tr.innerHTML = `<td><code>${a.timestamp.slice(11, 19)}</code></td>
          <td>${a.mode}</td>
          <td><strong>${a.decision}</strong></td>
          <td><code>${(a.reason_codes || []).join(', ') || 'NONE'}</code></td>
          <td>${a.caller_clearance} / <code>${a.target_egress}</code></td>`;
        atbody.appendChild(tr);
      });
    }

    async function toggleMode() {
      const next = currentMode === 'enforce' ? 'observe' : 'enforce';
      await fetch('/v1/admin/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-POD-Admin-Key': ADMIN_KEY },
        body: JSON.stringify({ mode: next })
      });
      await refreshState();
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

    loadPreset('allow');
    loadLlmConfig();
    loadPcFoldersDropdown();
    // Auto-run initial directory attestation and Prevalidator scan so verifiable English counts appear immediately
    attestSelectedDirectory();
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
    app = FastAPI(title="G1 Docket by G1183RT Security Labs — AI Gateway Prevalidator", version="0.1.0")
    logo_path = Path(__file__).resolve().parent / "g1_logo.png"

    if enforcer is None:
        key_dir = Path(os.environ.get("POD_KEY_DIR", "./.pod_keys"))
        keyring = Keyring(key_dir)
        store = InMemorySnapshotStore(keyring)
        snap_path = Path(snapshot_file or os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json"))
        if snap_path.exists():
            store.load_from_file(snap_path)
        mode = os.environ.get("POD_PREVALIDATOR_MODE", "enforce")
        enforcer = PrevalidatorEnforcer(snapshot_store=store, mode=mode)

    upstream_url = (upstream_gateway_url or os.environ.get("POD_UPSTREAM_GATEWAY_URL", "mock://local")).rstrip("/")
    engine_url = (engine_service_url or os.environ.get("POD_ENGINE_SERVICE_URL", "http://engine:8083")).rstrip("/")
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
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

    @app.post("/v1/admin/attest-directory")
    async def proxy_attest_directory(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> Any:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(f"{engine_url}/v1/attest-directory", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())

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
        elif directory_path:
            max_files = int(body.get("max_files", 120))
            try:
                target_dir, locator_base = resolve_pc_directory_path(directory_path)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

            for p in iter_scannable_files(target_dir, max_files=max_files):
                try:
                    rel_inside = p.relative_to(target_dir).as_posix()
                    sha = compute_file_sha256(p)
                    loc = f"{locator_base.rstrip('/')}/{rel_inside}"
                    file_candidates.append((rel_inside, loc, sha))
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
            outcome = enforcer.evaluate_request(
                payload=sim_payload,
                headers={"X-POD-Caller-Key": caller_key},
            )
            reasons = outcome.audit_entry.reason_codes
            is_pass = len(reasons) == 0 and outcome.allowed_to_forward

            if not snap_entry:
                att_state = "UNATTESTED"
                tier = "NONE"
                unattested_count += 1
                reason_detail = "UNATTESTED — No signed record in snapshot"
            elif snap_entry["content_sha256"].lower() != obs_sha.lower():
                att_state = "HASH_DRIFT"
                tier = snap_entry["tier"]
                unattested_count += 1
                hash_drift_count += 1
                reason_detail = "UNATTESTED — File content SHA-256 modified since attestation"
            else:
                att_state = f"ATTESTED ({snap_entry['status'].upper()})"
                tier = snap_entry["tier"]
                if is_pass:
                    if outcome.audit_entry.decision == "strip":
                        strip_count += 1
                        reason_detail = "PASSED (STRIP) — Confidential content stripped per policy"
                    else:
                        allow_count += 1
                        reason_detail = "PASSED (ALLOW) — Hash & policy verified"
                else:
                    policy_denied_count += 1
                    reason_detail = f"BLOCKED — {', '.join(reasons)}"

            if is_pass:
                passed_count += 1
                verdict = "PASS (STRIP)" if outcome.audit_entry.decision == "strip" else "PASS (ALLOW)"
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
        pure_unattested = unattested_count - hash_drift_count
        english_summary = (
            f"Prevalidator scanned {total_count} total file(s) in '{dir_label}': "
            f"{passed_count} of {total_count} file(s) PASSED ({allow_count} Allowed, {strip_count} Stripped) and "
            f"{failed_count} of {total_count} file(s) DID NOT PASS "
            f"({pure_unattested} Unattested file(s) with no signed record, "
            f"{hash_drift_count} Modified/Hash-drift file(s), "
            f"{policy_denied_count} Policy/Clearance-blocked file(s))."
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
            "files": file_results,
        }

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        snap = enforcer.snapshot_store.get_active_snapshot()
        return {
            "status": "ok" if snap is not None else "stale_or_missing_snapshot",
            "mode": enforcer.mode,
            "snapshot_sequence": snap["sequence_number"] if snap else None,
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
    async def reload_snapshot(request: Request, x_pod_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
        if x_pod_admin_key != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-POD-Admin-Key")
        body = await request.json()
        if "envelope" in body:
            pred = enforcer.snapshot_store.load_from_envelope(body["envelope"])
        else:
            path = body.get("path") or os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json")
            pred = enforcer.snapshot_store.load_from_file(path)
        return {"loaded": True, "snapshot_id": pred["snapshot_id"], "sequence_number": pred["sequence_number"]}

    return app
