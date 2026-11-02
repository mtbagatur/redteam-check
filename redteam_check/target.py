"""HTTP target: sends one prompt, returns the assistant's text. Standard library only."""
import json
import os
import re
import time
import urllib.error
import urllib.request

PRESETS = {
    # OpenAI-compatible chat endpoints (OpenAI, Azure OpenAI, LiteLLM, vLLM, Ollama /v1 ...).
    "openai": {
        "body": '{"model": "{{model}}", "messages": [{"role": "system", "content": "{{system}}"}, '
                '{"role": "user", "content": "{{prompt}}"}]}',
        "response_path": "choices.0.message.content",
    },
}


class TargetError(Exception):
    pass


def _expand_env(value: str) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), value)


def _dig(data, path: str):
    for part in path.split(".") if path else []:
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


class HttpTarget:
    def __init__(self, cfg: dict):
        preset = PRESETS.get(cfg.get("preset", ""), {})
        self.url = _expand_env(cfg["url"])
        self.method = cfg.get("method", "POST")
        self.headers = {"Content-Type": "application/json",
                        **{k: _expand_env(v) for k, v in cfg.get("headers", {}).items()}}
        self.body = cfg.get("body", preset.get("body", '{"message": "{{prompt}}"}'))
        self.response_path = cfg.get("response_path", preset.get("response_path", "reply"))
        self.vars = {k: str(v) for k, v in cfg.get("vars", {}).items()}
        self.timeout = float(cfg.get("timeout", 60))
        self.retries = int(cfg.get("retries", 2))

    def render(self, prompt: str) -> bytes:
        values = {**self.vars, "prompt": prompt}
        # json.dumps(...)[1:-1] escapes quotes and newlines so the value is safe inside a JSON string.
        body = re.sub(r"\{\{(\w+)\}\}", lambda m: json.dumps(values.get(m.group(1), ""))[1:-1], self.body)
        json.loads(body)  # fail early on a broken template
        return body.encode()

    def send(self, prompt: str) -> str:
        req = urllib.request.Request(self.url, data=self.render(prompt), headers=self.headers, method=self.method)
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    text = _dig(json.loads(r.read().decode()), self.response_path)
                    return text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    time.sleep(float(e.headers.get("Retry-After") or 2 ** attempt))
                    continue
                raise TargetError(f"HTTP {e.code}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise TargetError(str(getattr(e, "reason", e))) from e
            except (KeyError, IndexError, ValueError) as e:
                raise TargetError(f"response_path '{self.response_path}' not found in the response") from e
        raise TargetError("no response")
