import argparse
import sys
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.exceptions import SigmaError

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dirs", nargs="+", type=Path)
    args = parser.parse_args()

    backend = SplunkBackend()
    success = 0
    errors = 0
    error_reasons = {}

    for d in args.dirs:
        for p in d.rglob("*.yml"):
            try:
                content = p.read_text(encoding="utf-8")
                collection = SigmaCollection.from_yaml(content)
                result = backend.convert(collection)
                success += 1
            except Exception as e:
                errors += 1
                reason = type(e).__name__ + ": " + str(e)
                error_reasons[p] = reason

    print(f"Total processed: {success + errors}")
    print(f"Success: {success}")
    print(f"Errors: {errors}")
    if errors > 0:
        print("\nErrors breakdown:")
        for p, reason in error_reasons.items():
            print(f" - {p}: {reason}")

if __name__ == "__main__":
    main()
