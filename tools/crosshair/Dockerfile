# Trusted CrossHair toolchain image. Build-time network is used only to fetch the
# hash-pinned wheels below; analysis jobs run it under gVisor with --network none.
#   docker --context default build -t colossus-crosshair:0.0.113 tools/crosshair
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
COPY requirements.txt /opt/crosshair/requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-compile \
        --only-binary=:all: --require-hashes -r /opt/crosshair/requirements.txt \
    && python -m crosshair --help >/dev/null \
    && python -c "import importlib.metadata as m; assert m.version('crosshair-tool') == '0.0.113'; assert m.version('z3-solver') == '5.4.1.0'"
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0
LABEL org.colossus.managed="true" org.colossus.toolchain="crosshair-0.0.113-z3-5.4.1.0"
USER 1000:1000
WORKDIR /work
