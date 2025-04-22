import json
import argparse
import os


def countPackageLock(filepath):
    """Counts the number of dependencies in a given package-lock.json file."""
    try:
        lockPath = os.path.join(os.path.dirname(__file__), filepath)
        file = open(lockPath, "r")
        contents = json.load(file)
        # print(json.dumps(contents, indent=4))

        # lock file has a "packages" object, just count the number of keys
        packages = contents.get("packages", {})
        count = len(packages.keys())

        return count
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return -1


def main():
    parser = argparse.ArgumentParser(
        description="Count dependencies in package-lock.json"
    )
    parser.add_argument("filename")

    args = parser.parse_args()

    count = countPackageLock(args.filename)

    print(f"Number of dependencies in {args.filename}: {count}")
    return count


if __name__ == "__main__":
    main()
