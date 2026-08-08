# VulnTriage Crew -- container image.
#
# Built so that `docker run vulntriage` produces a real triage report with no
# arguments, no .env, no API key and no network: the default command is the
# deterministic offline pipeline over the sample export. Everything live --
# Tenable findings, KEV/EPSS/NVD intel, the LLM crew -- is opt-in at run time
# through flags and environment, never baked into the image.
#
# Nothing secret is copied in. `.env` is excluded by .dockerignore and supplied
# at run time by compose's env_file, so an image built here can be pushed
# anywhere without carrying a credential.

FROM python:3.11-slim

# - PYTHONDONTWRITEBYTECODE: no .pyc litter in a layer that will be thrown away
# - PYTHONUNBUFFERED: `docker logs` shows progress as it happens, not at exit
# - PYTHONIOENCODING: the reports and the run summary contain em-dashes, and a
#   container without a locale would otherwise raise UnicodeEncodeError on them
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app

# Requirements first, as their own layer: dependency resolution for crewai is by
# far the slowest step here, and code edits must not invalidate it.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Only what actually runs. Tests, scripts, docs and the markdown live in the
# repo, not in the runtime image -- and listing the sources explicitly means a
# new file at the root cannot be swept in by accident.
COPY main.py ./
COPY vulntriage/ ./vulntriage/
COPY data/ ./data/

# Not root. The container's only job is to read a scanner export and write a
# report, and it needs no more authority than that.
#
# `output` is created and owned here so a fresh `docker run` with no volume
# still writes its four artifacts. A bind mount over this path brings the host's
# ownership with it; on Docker Desktop that is transparent, on a Linux host see
# the README note about matching the uid.
RUN useradd --create-home --uid 10001 vulntriage \
    && mkdir -p /app/output \
    && chown -R vulntriage:vulntriage /app
USER vulntriage

# ENTRYPOINT + CMD rather than one line, so the default is a working run and
# `docker run <image> --source tenable --scan-id 58373` overrides only the args.
ENTRYPOINT ["python", "main.py"]
CMD ["--source", "mock", "--offline"]
