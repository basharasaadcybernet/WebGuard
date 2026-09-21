# Third-party notices

WebGuard depends on third-party software that remains subject to its own license. The project MIT
License applies only to the original WebGuard code and documentation.

## Python runtime dependencies

The v0.1.0 runtime dependency set includes software distributed under permissive or file-level
copyleft licenses, including:

- FastAPI, Pydantic, Rich, and Typer — MIT;
- HTTPX and HTTPCore — BSD-3-Clause;
- IDNA — BSD-3-Clause;
- Uvicorn — BSD-3-Clause; and
- Certifi — MPL-2.0.

Their transitive dependencies include MIT, BSD, ISC, PSF, and MPL-2.0 components. The exact
reviewed container resolution is recorded in `requirements.production.txt`. A normal Wheel install
resolves the compatible ranges declared in `pyproject.toml`; installed distributions carry their
own metadata and license files.

## Frontend runtime

The production browser bundle includes React and React DOM, distributed under MIT. Build and test
tooling recorded in `frontend/package-lock.json` includes additional MIT, BSD, Apache-2.0, ISC,
MPL-2.0, CC0-1.0, CC-BY-4.0, MIT-0, and BlueOak-1.0.0 packages. Those tools are used to build or
test the application and are not all shipped as runtime JavaScript.

## Container bases

The backend and frontend are built from the official Python, Node, and Nginx Unprivileged images.
Those images and the operating-system packages they contain retain their own upstream licenses and
notices. Image digests should be recorded for each published release build.

This summary is provided for release transparency. The authoritative terms are the license files
and metadata supplied by each dependency and base image.
