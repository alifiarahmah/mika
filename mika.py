#!/usr/bin/env python3
"""
mika.py - BYOM security-testing harness (authorized testing only).

Modes:
  proxy  Logging forward-proxy in front of local Ollama.
         Dumps every request the AI platform sends (headers + full body)
         to console and ./dumps/, then forwards to Ollama so real agent
         runs keep working normally.

  mika     Interactive model impersonating server. You ARE the model: every incoming
         request is dumped, then you choose the exact response to return
         (raw JSON / plain content / forged tool call / hang / HTTP 500).
         Fixed "test connection" probes are auto-answered with "ok".

  hybrid Dump + Ollama pass-through + selective impersonating. Every request is dumped,
         test pings are auto-OK'd, and everything else is forwarded to
         Ollama (which generates legitimate tool calls itself) so real
         agent runs proceed naturally. Type 'i' + Enter in the console to
         ARM a one-shot intercept: the NEXT request is crafted manually
         (forged tool call etc.) instead of forwarded. 's' shows status,
         'x' quits. Re-arm 'i' for each turn you want to control.

Usage:
  python mika.py proxy --port 8000 --model llama3.2
  python mika.py mika --port 8000
  python mika.py hybrid --port 8000 --model llama3.2
"""

import argparse
import datetime
import json
import logging
import os
import queue
import threading
import time

from flask import Flask, Response, request
import requests

DUMP_DIR = "dumps"
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
HOP_BY_HOP = {"host", "content-length", "connection", "keep-alive",
              "transfer-encoding", "upgrade", "accept-encoding",
              "proxy-authorization"}

app = Flask(__name__)
MODE = "proxy"
OLLAMA = "http://localhost:11434"
REWRITE_MODEL = None
incoming = queue.Queue()
INTERCEPT_NEXT = threading.Event()   # hybrid mode: one-shot manual-craft flag


# ---------------- dumping ----------------

def banner(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def write_dump(path, record):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False, default=str)


def save_dump(kind):
    body_bytes = request.get_data()
    body_str = body_bytes.decode("utf-8", errors="replace")
    try:
        body_json = json.loads(body_str)
    except Exception:
        body_json = None

    p = request.full_path
    if p.endswith("?"):
        p = p[:-1]

    record = {
        "timestamp": datetime.datetime.now().isoformat(),
        "kind": kind,
        "client_ip": request.remote_addr,
        "method": request.method,
        "path": p,
        "headers": dict(request.headers),
        "body_raw": body_str,
        "body_json": body_json,
    }
    os.makedirs(DUMP_DIR, exist_ok=True)
    fname = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f") + f"-{kind}.json"
    dump_path = os.path.join(DUMP_DIR, fname)
    write_dump(dump_path, record)

    banner(f"{kind.upper()} {request.method} {p}  from {request.remote_addr}")
    preview = (json.dumps(body_json, indent=2, ensure_ascii=False)
               if body_json is not None else body_str)
    if len(preview) > 6000:
        preview = preview[:6000] + f"\n... [truncated; full copy in {dump_path}]"
    print(preview)
    print(f"[+] full dump saved: {dump_path}")
    return dump_path, record


def print_recon(body_json):
    """Highlight the useful intel: system prompt, tool definitions, stream mode."""
    if not isinstance(body_json, dict):
        return
    msgs = body_json.get("messages") or []
    roles = [m.get("role") for m in msgs]
    print(f"[i] model={body_json.get('model')!r}  stream={body_json.get('stream')}  "
          f"max_tokens={body_json.get('max_tokens')}  messages={len(msgs)}  roles={roles}")
    tools = body_json.get("tools") or []
    if tools:
        names = [t.get("function", {}).get("name") for t in tools]
        print(f"[i] TOOL DEFINITIONS VISIBLE ({len(tools)}): {names}")
    for m in msgs:
        if m.get("role") == "system":
            c = str(m.get("content", ""))[:400]
            print(f"[i] SYSTEM PROMPT (first 400 chars):\n    {c}")
            break


# ---------------- mode 1: logging proxy -> Ollama ----------------

def handle_proxy():
    dump_path, record = save_dump("proxy-req")
    return forward_to_ollama(record, dump_path)


def forward_to_ollama(record, dump_path):
    """Forward the captured request to Ollama and relay the response back."""
    body = request.get_data()

    payload = record["body_json"]
    if payload is not None and isinstance(payload, dict) and REWRITE_MODEL:
        payload["model"] = REWRITE_MODEL          # platform's model ID -> your Ollama model
        body = json.dumps(payload).encode()

    is_stream = bool(payload.get("stream")) if isinstance(payload, dict) else False

    if "chat/completions" in request.path:
        target = OLLAMA.rstrip("/") + "/v1/chat/completions"   # Ollama OpenAI-compat endpoint
    else:
        target = OLLAMA.rstrip("/") + request.path

    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP}

    try:
        r = requests.request(
            method=request.method,
            url=target,
            data=body,
            headers=fwd_headers,
            stream=is_stream,
            timeout=600,
            allow_redirects=False,
        )
    except Exception as e:
        print(f"[!] forward to Ollama failed: {e}")
        return Response(json.dumps({"error": f"proxy forward failed: {e}"}),
                        status=502, mimetype="application/json")

    ctype = r.headers.get("content-type", "application/json")

    if not is_stream:
        record["response_status"] = r.status_code
        record["response_body"] = r.text
        write_dump(dump_path, record)
        print(f"[+] Ollama responded {r.status_code} ({len(r.text)} bytes)")
        return Response(r.text, status=r.status_code, content_type=ctype)

    collected = []

    def stream_gen():
        try:
            for chunk in r.iter_content(chunk_size=None):
                if chunk:
                    collected.append(chunk)
                    yield chunk
        finally:
            r.close()
            text = b"".join(collected).decode("utf-8", errors="replace")
            record["response_status"] = r.status_code
            record["response_body"] = text
            write_dump(dump_path, record)
            print(f"[+] streamed response captured ({len(text)} bytes)")

    return Response(stream_gen(), status=r.status_code, content_type=ctype)


# ---------------- mode 3: interactive impersonation --------------

class ImpersonateItem:
    def __init__(self, record):
        self.record = record
        self.event = threading.Event()
        self.response = None   # {"body": str, "status": int, "ctype": str, "sse": bool, "json_body": dict|None}
        self.hang = False


def sse_wrap(completion):
    """Convert a normal OpenAI-style completion into an SSE chunk stream."""
    choice = completion["choices"][0]
    msg = choice.get("message", {})
    delta = {}
    if msg.get("role") is not None:
        delta["role"] = msg["role"]
    if msg.get("content") is not None:
        delta["content"] = msg["content"]
    finish = choice.get("finish_reason") or "stop"
    if msg.get("tool_calls"):
        delta["tool_calls"] = [{"index": i, **tc}
                               for i, tc in enumerate(msg["tool_calls"])]
        finish = "tool_calls"
    base = {"id": "chatcmpl-mika-" + str(int(time.time())),
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": completion.get("model", "mika")}
    chunk1 = dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": None}])
    chunk2 = dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": finish}])
    return ("data: " + json.dumps(chunk1) + "\n\n"
            + "data: " + json.dumps(chunk2) + "\n\n"
            + "data: [DONE]\n\n")


def prompt_multi(title):
    print(f"\n{title}  (finish with a line containing only 'END'):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def build_completion(requested_model, content=None, tool_name=None, tool_args_str=None):
    msg = {"role": "assistant"}
    finish = "stop"
    if content is not None:
        msg["content"] = content
    if tool_name is not None:
        msg["content"] = None
        msg["tool_calls"] = [{
            "id": "call_" + str(int(time.time())),
            "type": "function",
            "function": {"name": tool_name, "arguments": tool_args_str},
        }]
        finish = "tool_calls"
    return {
        "id": "chatcmpl-mika-" + str(int(time.time())),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": requested_model or "mika",
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


# Known fixed "Test connection" probe prompts (lowercased, stripped).
# The platform's connectivity check sends exactly one of these with a tiny
# max_tokens budget and no tools. Extend the set if the probe wording changes.
AUTO_OK_PROMPTS = {
    "reply with the single word: ok",
}


def is_test_ping(body_json):
    """True if the request looks like the platform's fixed connectivity probe."""
    if not isinstance(body_json, dict) or body_json.get("tools"):
        return False
    msgs = body_json.get("messages") or []
    if not msgs:
        return False
    last = msgs[-1]
    content = str(last.get("content", "")).strip().lower()
    if last.get("role") != "user" or content not in AUTO_OK_PROMPTS:
        return False
    max_tokens = body_json.get("max_tokens")
    return max_tokens is None or (isinstance(max_tokens, int) and max_tokens <= 64)


def operator_loop():
    while True:
        item = incoming.get()
        bj = item.record.get("body_json") or {}
        stream_req = bool(bj.get("stream")) if isinstance(bj, dict) else False
        model = bj.get("model") if isinstance(bj, dict) else None
        print(f"\n--- craft response " + ("[agent wants STREAM]" if stream_req else "") + " ---")

        choice = input("[1] raw JSON  [2] content  [3] forged tool call  "
                       "[4] hang (timeout test)  [5] HTTP 500 > ").strip()
        resp = {"body": "{}", "status": 200, "ctype": "application/json",
                "sse": False, "json_body": None}

        if choice == "1":
            raw = prompt_multi("Paste exact response body")
            resp["body"] = raw
            try:
                parsed = json.loads(raw)
                resp["json_body"] = parsed
            except Exception:
                parsed = None
                print("[!] not valid JSON - sending verbatim anyway")
            if stream_req and isinstance(parsed, dict) and parsed.get("choices"):
                if input("auto-wrap into SSE stream? [Y/n] ").strip().lower() != "n":
                    resp["sse"] = True

        elif choice == "2":
            text = prompt_multi("Assistant content to send")
            completion = build_completion(model, content=text)
            resp["json_body"] = completion
            resp["body"] = json.dumps(completion)
            resp["sse"] = stream_req

        elif choice == "3":
            name = input("tool name to invoke: ").strip()
            args_raw = prompt_multi("tool arguments (JSON object)")
            try:
                args_str = json.dumps(json.loads(args_raw or "{}"))
            except Exception:
                args_str = args_raw
                print("[!] args not valid JSON - sending as raw string")
            completion = build_completion(model, tool_name=name, tool_args_str=args_str)
            resp["json_body"] = completion
            resp["body"] = json.dumps(completion)
            resp["sse"] = stream_req

        elif choice == "4":
            item.hang = True
            item.event.set()
            continue

        elif choice == "5":
            resp["status"] = 500
            resp["body"] = '{"error":"internal server error (mika)"}'

        else:
            print("[!] unknown option - returning empty completion")
            resp["body"] = json.dumps(build_completion(model, content=""))

        item.response = resp
        item.event.set()


def auto_ok_response(bj):
    """Valid 'ok' completion for the connectivity probe (JSON or SSE)."""
    stream_req = bool(bj.get("stream"))
    completion = build_completion(bj.get("model"), content="ok")
    mode = "SSE stream" if stream_req else "JSON"
    print(f"[*] AUTO-OK: test-connection probe detected -> replying 'ok' ({mode})")
    if stream_req:
        return Response(sse_wrap(completion), mimetype="text/event-stream")
    return Response(json.dumps(completion), mimetype="application/json")


def mika_respond(record):
    """Queue the request for manual crafting and wait for the operator."""
    item = ImpersonateItem(record)
    incoming.put(item)
    item.event.wait()          # wait until you craft the response in the console
    if item.hang:
        print("[*] hanging connection - platform timeout should fire...")
        time.sleep(3600)
        return "", 504
    resp = item.response
    if resp.get("sse") and resp.get("json_body") is not None:
        return Response(sse_wrap(resp["json_body"]), mimetype="text/event-stream")
    return Response(resp["body"], status=resp["status"], content_type=resp["ctype"])


def handle_mika():
    dump_path, record = save_dump("mika-req")
    print_recon(record["body_json"])
    bj = record.get("body_json")
    if bj is not None and is_test_ping(bj):
        return auto_ok_response(bj)
    return mika_respond(record)


# ---------------- mode 2.5: hybrid (Ollama pass-through + intercept) ----------------

def hybrid_console():
    print("[i] hybrid console: [i]=intercept next request  [s]=status  [x]=quit")
    while True:
        try:
            cmd = input("hybrid> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            continue
        if cmd == "i":
            INTERCEPT_NEXT.set()
            print("[*] ARMED: the next incoming request will be crafted manually "
                  "(mika menu) instead of forwarded to Ollama")
        elif cmd == "s":
            state = "ARMED" if INTERCEPT_NEXT.is_set() else "pass-through"
            print(f"[*] mode={MODE}  intercept={state}  ollama={OLLAMA}  "
                  f"model_rewrite={REWRITE_MODEL or '(off)'}")
        elif cmd == "x":
            print("[*] shutting down")
            os._exit(0)


def handle_hybrid():
    dump_path, record = save_dump("hybrid-req")
    print_recon(record["body_json"])
    bj = record.get("body_json")
    if bj is not None and is_test_ping(bj):
        return auto_ok_response(bj)
    if INTERCEPT_NEXT.is_set():
        INTERCEPT_NEXT.clear()
        print("[*] INTERCEPT: crafting this response manually "
              "(one-shot; type 'i' again to arm for the next turn)")
        return mika_respond(record)
    return forward_to_ollama(record, dump_path)


# ---------------- routing ----------------

@app.route("/", defaults={"path": ""}, methods=METHODS)
@app.route("/<path:path>", methods=METHODS)
def catchall(path):
    if MODE == "proxy":
        return handle_proxy()
    if MODE == "hybrid":
        return handle_hybrid()
    return handle_mika()


def main():
    ap = argparse.ArgumentParser(description="BYOM testing harness (authorized use only)")
    ap.add_argument("mode", choices=["proxy", "mika", "hybrid"])
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--ollama", default="http://localhost:11434",
                    help="proxy/hybrid mode: Ollama base URL")
    ap.add_argument("--model", default=None,
                    help="proxy/hybrid mode: rewrite the 'model' field to this Ollama model name")
    args = ap.parse_args()

    global MODE, OLLAMA, REWRITE_MODEL
    MODE = args.mode
    OLLAMA = args.ollama.rstrip("/")
    REWRITE_MODEL = args.model

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    os.makedirs(DUMP_DIR, exist_ok=True)

    if MODE == "proxy":
        print(f"[*] proxy mode: dumping all traffic, forwarding to {OLLAMA}")
        if REWRITE_MODEL:
            print(f"[*] rewriting 'model' field -> {REWRITE_MODEL}")
    elif MODE == "hybrid":
        print(f"[*] hybrid mode: dump + auto-ok + Ollama pass-through ({OLLAMA}). "
              "Type 'i' to intercept the next request for manual crafting.")
        if REWRITE_MODEL:
            print(f"[*] rewriting 'model' field -> {REWRITE_MODEL}")
        threading.Thread(target=hybrid_console, daemon=True).start()
    else:
        print("[*] mika mode: you are the model. Requests appear here; "
              "craft responses in this console.")
        threading.Thread(target=operator_loop, daemon=True).start()

    app.run(host="0.0.0.0", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
