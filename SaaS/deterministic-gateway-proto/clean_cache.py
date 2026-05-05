#!/usr/bin/env python3
"""Remove all __pycache__ directories."""
import os, shutil
count = 0
for root, dirs, files in os.walk('/Volumes/Code/SSIP/SaaS/deterministic-gateway-proto'):
    for d in list(dirs):
        if d == '__pycache__':
            path = os.path.join(root, d)
            shutil.rmtree(path)
            print(f'Removed: {path}')
            count += 1
            dirs.remove(d)
print(f'Removed {count} __pycache__ directories')
