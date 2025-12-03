from pathlib import Path
from setuptools import setup, find_packages


this_dir = Path(__file__).parent
readme = (this_dir / "README.md").read_text(encoding="utf-8") if (this_dir / "README.md").exists() else ""

setup(
    name="hulud-scan",
    version="0.1.0",
    description="NPM Package Threat Scanner for HULUD worm-compromised packages",
    long_description=readme,
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    license="MIT",
    author="Hulud Security",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "click>=8.1",
        "semantic_version>=2.10",
    ],
    entry_points={
        "console_scripts": [
            "npm-scan=hulud_scan.scan_npm_threats:cli",
        ]
    },
)
