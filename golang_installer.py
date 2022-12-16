#!/usr/bin/env python3

# pylint: disable=missing-module-docstring, missing-function-docstring

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

# JSON that includes information about the latest version and other
# available versions (pre-release versions are not included)
DL_INFO = "https://golang.org/dl/?mode=json"

# Markers used to find the start end end of part of the profile
# added by this script
PROFILE_START = "## Golang installer begin ##"
PROFILE_END = "## Golang installer end ##"

# Get platform name
if sys.platform == "darwin":
    OS_NAME = "darwin"
elif sys.platform == "linux":
    OS_NAME = "linux"
else:
    raise Exception("Unsupported platform")

# Get arch name
if platform.machine() == "x86_64":
    ARCH = "amd64"
elif platform.machine() in ["aarch64", "armv8"]:
    ARCH = "arm64"
elif platform.machine() in ["armv6", "armv7l"]:
    ARCH = "arm"
elif platform.machine().find("386") != -1:
    ARCH = "386"
else:
    raise Exception("Unsupported architecture")


def members(tar_file):
    # Based on https://stackoverflow.com/a/43094365
    go_str = "go/"
    go_len = len(go_str)
    for member in tar_file.getmembers():
        if member.path[0:go_len] == go_str:
            member.path = member.path[go_len:]
            yield member


def create_file(profile_file):
    # Get dirpath
    dirpath = os.path.dirname(profile_file)
    # Create dir if not exists
    os.makedirs(dirpath, exist_ok=True)
    # Create file if not exists
    if not os.path.exists(profile_file):
        with open(profile_file, "w") as file:
            file.write("")


def remove_old_profile_data(profile_file):
    with open(profile_file, "r") as file:
        profile_data = file.read()
    with open(profile_file, "w") as file:
        flag = True
        lines = profile_data.split("\n")
        for idx, line in enumerate(lines):
            if line == PROFILE_START:
                flag = False
            elif line == PROFILE_END:
                flag = True
                continue

            if not flag:
                continue

            if idx == 0:
                file.write(line)
            else:
                file.write(f"\n{line}")
        if lines[-1] != "":
            file.write("\n")


def shell_profile(prefix):
    myshell = os.environ.get("SHELL")
    if myshell is None:
        return False
    test_bash = (
        len(
            subprocess.run(
                [myshell, "-c", "echo $BASH_VERSION"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            ).stdout.strip()
        )
        > 0
    )
    test_zsh = (
        len(
            subprocess.run(
                [myshell, "-c", "echo $ZSH_VERSION"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            ).stdout.strip()
        )
        > 0
    )
    test_fish = (
        len(
            subprocess.run(
                [myshell, "-c", "echo $FISH_VERSION"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            ).stdout.strip()
        )
        > 0
    )

    if test_bash or test_zsh:
        if test_zsh:
            profile_file = os.path.expanduser("~/.zshrc")
        else:
            profile_file = os.path.expanduser("~/.bashrc")
        create_file(profile_file)
        remove_old_profile_data(profile_file)
        with open(profile_file, "a") as file:
            file.write(f"{PROFILE_START}\n")
            file.write(f"export GOROOT={prefix}\n")
            file.write(f"export GOPATH=$HOME/go\n")
            file.write(f"export PATH=$GOROOT/bin:$PATH\n")
            file.write(f"export PATH=$GOPATH/bin:$PATH\n")
            file.write(f"{PROFILE_END}\n")
        return True

    if test_fish:
        profile_file = os.path.expanduser("~/.config/fish/config.fish")
        create_file(profile_file)
        remove_old_profile_data(profile_file)
        with open(profile_file, "a") as file:
            file.write(f"{PROFILE_START}\n")
            file.write(f"set -gx GOROOT {prefix}\n")
            file.write(f"set -gx GOPATH $HOME/go\n")
            file.write(f"set -gx PATH $GOROOT/bin $PATH\n")
            file.write(f"set -gx PATH $GOPATH/bin $PATH\n")
            file.write(f"{PROFILE_END}")
        return True
    return False


def version_list(req_json):
    print("Available versions:")
    for version in req_json:
        print(f"  {version['version']}")


def get_latest_version(req_json):
    try:
        version = req_json[0]["version"]
    except (IndexError, KeyError):
        raise Exception("No version found")
    return version


def find_url_and_sha256(resp_json, version, osname, arch):
    download_url = None
    sha256 = None
    for item in resp_json:
        try:
            if item["version"] == version:
                for file in item["files"]:
                    if file["os"] == osname and file["arch"] == arch:
                        download_url = file["filename"]
                        sha256 = file["sha256"]
                        break
        except (KeyError, IndexError):
            raise Exception("Unexpected structure")
    if not download_url or not sha256:
        raise Exception("Unable to find download url")
    return download_url, sha256


def download_and_install(response_json, version, prefix, force):
    download_url, sha256 = find_url_and_sha256(response_json, version, OS_NAME, ARCH)

    print(f"Downloading {download_url}")
    print(f"SHA256: {sha256}")

    if os.path.exists(prefix):
        if not force:
            # Check if same version
            with open(os.path.join(prefix, "VERSION"), "r") as file:
                version_file = file.read()

            # If the same version, raise exception
            if version_file == version:
                raise Exception("Already installed")

        print("Removing old installation...")
        shutil.rmtree(prefix)
        print("Done removing old installation")

    buffer_size = 2 ** 20
    new_hash = hashlib.sha256(b"")
    with tempfile.TemporaryFile() as temp_file:
        req = urllib.request.urlopen(
            f"https://storage.googleapis.com/golang/{download_url}"
        )
        data = True
        while data:
            data = req.read(buffer_size)
            temp_file.write(data)
            new_hash.update(data)
        temp_file.seek(0)
        if new_hash.hexdigest().lower() != sha256.lower():
            raise Exception("SHA256 mismatch")
        print("SHA256 OK")
        print("Extracting...")
        with tarfile.open(fileobj=temp_file, mode="r:gz") as tar:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(tar, prefix, members=members(tar))
        print("Done extracting")

    print("Setting up environment...")
    if shell_profile(prefix):
        print("Done setting up environment")
    else:
        print("Unable to set up environment")


def main():
    parser = argparse.ArgumentParser(description="Golang installer")
    parser.add_argument(
        "-l", "--list", action="store_true", help="List available versions"
    )
    parser.add_argument("-v", "--version", help="Golang version", required=False)
    parser.add_argument(
        "-p", "--prefix", help="Golang prefix", default=os.path.expanduser("~/.go")
    )
    parser.add_argument("-f", "--force", action="store_true", help="Force installation")
    args = parser.parse_args()
    req = urllib.request.urlopen(DL_INFO)
    try:
        response_json = json.loads(req.read().decode("utf-8"))
    except ValueError:
        raise Exception("Invalid response")

    if args.list:
        version_list(response_json)
        return

    if args.version:
        version = args.version
    else:
        version = get_latest_version(response_json)

    prefix = args.prefix
    force = args.force

    download_and_install(response_json, version, prefix, force)


if __name__ == "__main__":
    main()
