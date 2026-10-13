#!/usr/bin/env python3
"""Asset-catalog scenarios for inspect_asset_catalog and what the ORIGINAL REA derives from them.

Each scenario is a bundle layout (built into a temp directory, also by the Rust test), a page, and
REA's result (discovery, hashing, paging, Interface Builder key join, errors) computed with
`replay_assets.mjs` using the records of tracewise's own catalog reader.

usage: python3 gen_assets.py <cargo-example-car_json> <out-scenarios.json>
"""
import hashlib
import json
import os
import plistlib
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import gen_fixtures as g  # noqa: E402

IBTOOL = lambda objects: {  # noqa: E731
    "com.apple.ibtool.document.objects": objects,
    "com.apple.ibtool.document.connections": {},
    "com.apple.ibtool.document.hierarchy": [],
    "com.apple.ibtool.document.classes": {},
}

EXECUTABLE = g.macho_image(commands=[g.build_version_command(1)])
INFO = g.info_plist("Mac")


def base_layout():
    return [
        {"path": "Contents/Info.plist", "text_b64": __import__("base64").b64encode(INFO if isinstance(INFO, bytes) else INFO.encode()).decode()},
        {"path": "Contents/MacOS/Mac", "bytes_b64": __import__("base64").b64encode(EXECUTABLE).decode()},
    ]


def nib(path, objects):
    return {"path": path, "nib": IBTOOL(objects)}


SCENARIOS = [
    {"id": "mac_default", "layout": [{"path": "Contents/Resources/Assets.car", "source": "vendor/assets_mac.car"}], "page": {}},
    {"id": "mac_page", "layout": [{"path": "Contents/Resources/Assets.car", "source": "vendor/assets_mac.car"}],
     "page": {"offset": 10, "limit": 5}},
    {"id": "mac_page_end", "layout": [{"path": "Contents/Resources/Assets.car", "source": "vendor/assets_mac.car"}],
     "page": {"offset": 70, "limit": 50}},
    {"id": "mac_page_beyond", "layout": [{"path": "Contents/Resources/Assets.car", "source": "vendor/assets_mac.car"}],
     "page": {"offset": 500, "limit": 5}},
    {"id": "tv_matches",
     "layout": [
         {"path": "Contents/Resources/Assets.car", "source": "vendor/assets_tv.car"},
         nib("Contents/Resources/Legacy.nib", {
             "1": {"customClass": "A", "imageName": "d_tv"},
             "2": {"customClass": "B", "UIImageName": "ghost"},
             "3": {"customClass": "C", "label": "d_tv"},
             "4": {"customClass": "D", "image": ""},
             "5": {"customClass": "E", "NSImageName": "d_universal"},
         })],
     "page": {"limit": 3}},
    {"id": "mac_ambiguous",
     "layout": [
         {"path": "Contents/Resources/Assets.car", "source": "vendor/assets_mac.car"},
         nib("Contents/Resources/Legacy.nib", {"1": {"customClass": "A", "image": "d_mac"}})],
     "page": {"limit": 1}},
    {"id": "two_catalogs",
     "layout": [
         {"path": "Contents/Resources/Assets.car", "source": "vendor/assets_mac.car"},
         {"path": "Contents/Frameworks/Kit.framework/Resources/Assets.car", "source": "vendor/assets_tv.car"},
         {"path": "Contents/Resources/OtherAssets.car", "source": "vendor/assets_tv.car"},
         nib("Contents/Resources/Legacy.nib", {"1": {"customClass": "A", "imageName": "d_tv"}})],
     "page": {"offset": 70, "limit": 8}},
    {"id": "no_catalog", "layout": [], "page": {}},
    {"id": "symlink_and_file",
     "layout": [
         {"path": "Contents/Resources/Assets.car", "source": "vendor/assets_tv.car"},
         {"path": "Contents/Frameworks/Link-Assets.car", "symlink": "../Resources/Assets.car"}],
     "page": {"limit": 2}},
    {"id": "only_symlink", "layout": [{"path": "Contents/Resources/Assets.car", "symlink": "nowhere"}], "page": {}},
    {"id": "only_directory", "layout": [{"path": "Contents/Resources/Assets.car/inner.txt", "text": "x"}], "page": {}},
]


def build(root, layout, car_json):
    for item in base_layout() + layout:
        target = os.path.join(root, item["path"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if "symlink" in item:
            os.symlink(item["symlink"], target)
        elif "source" in item:
            with open(os.path.join(HERE, item["source"]), "rb") as source, open(target, "wb") as handle:
                handle.write(source.read())
        elif "nib" in item:
            with open(target, "wb") as handle:
                handle.write(plistlib.dumps(item["nib"], fmt=plistlib.FMT_XML))
        elif "bytes_b64" in item:
            with open(target, "wb") as handle:
                handle.write(__import__("base64").b64decode(item["bytes_b64"]))
        elif "text_b64" in item:
            with open(target, "wb") as handle:
                handle.write(__import__("base64").b64decode(item["text_b64"]))
        else:
            with open(target, "w") as handle:
                handle.write(item["text"])


def main(car_json, out):
    records = {}
    for name in ("assets_mac.car", "assets_tv.car"):
        path = os.path.join(HERE, "vendor", name)
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        records[digest] = subprocess.run([car_json, path], capture_output=True, text=True, check=True).stdout.strip()
    target_sha256 = hashlib.sha256(EXECUTABLE).hexdigest()
    finished = []
    with tempfile.TemporaryDirectory() as work:
        records_path = os.path.join(work, "records.json")
        json.dump(records, open(records_path, "w"))
        for scenario in SCENARIOS:
            root = os.path.join(work, scenario["id"] + ".app")
            build(root, scenario["layout"], car_json)
            page_path = os.path.join(work, scenario["id"] + ".page.json")
            json.dump(scenario["page"], open(page_path, "w"))
            expected_path = os.path.join(work, scenario["id"] + ".expected.json")
            subprocess.run(["node", os.path.join(HERE, "replay_assets.mjs"), root, target_sha256, page_path,
                            records_path, expected_path], check=True)
            layout = []
            for item in scenario["layout"]:
                if "nib" in item:
                    xml = plistlib.dumps(item["nib"], fmt=plistlib.FMT_XML)
                    item = {"path": item["path"], "text_b64": __import__("base64").b64encode(xml).decode()}
                layout.append(item)
            finished.append(dict(scenario, layout=layout, base=base_layout(), expected=json.load(open(expected_path))))
    json.dump({"target_sha256": target_sha256, "scenarios": finished}, open(out, "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
