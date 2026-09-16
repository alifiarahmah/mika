# MIKA — Model Impersonation Kit for AI System

A mini tool to help audit AI system with the Bring-Your-Own-Model (BYOM) architecture.

## Background

Many AI platforms let users register custom OpenAI-compatible model endpoints. In BYOM architecture where users is allowed to integrate their own model to the system, AI endpoint could also be an untrusted, attacker-controlled source of instructions. MIKA helps to investigate: *What happens when the model endpoint is actually malicious?*

## Modes

- `proxy`:	Logs everything the platform sends (headers + full JSON), then forwards to a real local model (e.g. Ollama) so the platform keeps working normally.
- `mika`:	***You*** are the model. Craft every response by hand: raw JSON, plain content, forged tool calls, connection hangs, HTTP 500s, etc.
- `hybrid`:	Proxy pass-through plus selective interception: type `i` to hand-craft the next turn (one-shot), let the real model handle everything else

## Quickstart

### Prerequisites

- Flask
- Requests
- Ollama (for `proxy`/`hybrid` mode)

### How to run

1. The attacker run MIKA, then add the endpoint in the platform's model pool.

    ```sh
    # proxy mode
    python mika.py proxy --port 8000 --model llama3.2:1b
    
    # mika mode
    python mika.py mika --port 8000

    # hybrid mode
    python mika.py hybrid --port 8000 --model llama3.2:1b
    # console keys:  i = arm one-shot intercept of next request
    #                s = status        x = shutdown
    ```

2. Send any prompt as user. This will make the platform's backend fetches the endpoint.

    Initially this will leak the agent's system prompt injected instructions, and the full tool inventory ([LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)), which could be added as findings as you wish. But I think this is expected behavior so treat this as stepping stone (reconnaisance result) for further attacks.

3. From the tool, the attacker can craft any response, including a forged `tool_calls` completion. The platform's agent loop executes it with its own privileges and returns the tool output in the next request.

    If they can, this can be categorized as [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).

Every request will be logged to `./dumps/<timestamp>-<kind>.json` with method, path,
headers, raw body and parsed JSON.
