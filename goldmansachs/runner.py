"""Small fixed handler invoked inside a pre-created OpenShell sandbox."""

import json
import sys
import urllib.error
import urllib.request

MAX_RESPONSE_BYTES = 4096


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        url = payload["url"]
        method = payload["method"].upper()
        if method not in {"GET", "POST"}:
            raise ValueError("method must be GET or POST")

        data = None
        headers = {"User-Agent": "ReverseOpenShell-MVP/0.1"}
        if method == "POST":
            data = json.dumps(payload.get("data", {})).encode()
            headers["content-type"] = "application/json"

        request = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            result = {
                "status": response.status,
                "body": body[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace"),
                "truncated": len(body) > MAX_RESPONSE_BYTES,
            }
        print(json.dumps({"ok": True, "result": result}))
        return 0
    except urllib.error.HTTPError as exc:
        print(json.dumps({"ok": False, "status": exc.code, "error": "http_error"}))
        return 0
    except (
        KeyError,
        ValueError,
        TypeError,
        urllib.error.URLError,
        TimeoutError,
    ) as exc:
        # Do not echo URLs, query parameters, request bodies, or exception text.
        print(json.dumps({"ok": False, "error": type(exc).__name__}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
