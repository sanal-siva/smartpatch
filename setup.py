"""Install the service and its offline UI as one distributable package."""
from pathlib import Path
from setuptools import find_packages, setup

ROOT = Path(__file__).parent
requirements = [line.strip() for line in (ROOT / 'requirements.txt').read_text().splitlines()
                if line.strip() and not line.lstrip().startswith('#')]

setup(
    name='sonic-smart-patch-intelligence',
    version='3.0.0',
    description='Central vulnerability evidence service for community SONiC',
    packages=find_packages(include=['app', 'app.*']),
    package_data={'app.ui': ['templates/*.html', 'static/css/*.css', 'static/js/*.js'], 'app.services': ['schemas/*.json']},
    include_package_data=False,
    install_requires=requirements,
    python_requires='>=3.10',
    entry_points={'console_scripts': ['intelligence-service=app.main:run_server']},
)
