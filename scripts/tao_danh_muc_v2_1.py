"""Sinh danh mục ③ v2.1 = v2 + ProcessGuid ở nguồn Sysmon có trường đó. Không ghi đè tệp có sẵn."""
import argparse
from pathlib import Path

import yaml

from cti_hunt import config
from cti_hunt.stages import s3_telemetry

SOURCE = 'configs/telemetry_catalog_v2.yaml'
TARGET = 'configs/telemetry_catalog_v2_1.yaml'


def render(root: Path) -> bytes:
    doc = yaml.safe_load((root / SOURCE).read_text(encoding='utf-8'))
    out = s3_telemetry.add_process_guid(doc, '1.3')
    # Same writer as the N2 generator, so the diff against v2 is only the added lines.
    return yaml.safe_dump(out, allow_unicode=True, sort_keys=False).encode('utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=config.ROOT)
    args = parser.parse_args(argv)
    with open(args.root / TARGET, 'xb') as f:
        f.write(render(args.root))
    s3_telemetry.load_catalog(args.root / TARGET)
    print(f'Đã ghi {TARGET}')


if __name__ == '__main__':
    main()
