FROM mcr.microsoft.com/dotnet/sdk@sha256:1b955f179b02df4f0eb5fadedaa898cbe44d620a64aab52eec72c8e91d1355b5 AS compiler
RUN apt-get update && apt-get install -y --no-install-recommends default-jdk-headless && rm -rf /var/lib/apt/lists/*
COPY dafny-source.tar.gz /tmp/dafny-source.tar.gz
RUN mkdir /src && tar -xzf /tmp/dafny-source.tar.gz --strip-components=1 -C /src
WORKDIR /src
RUN dotnet publish Source/DafnyDriver/DafnyDriver.csproj -c Release --self-contained false -o /opt/dafny

FROM mcr.microsoft.com/dotnet/sdk@sha256:1b955f179b02df4f0eb5fadedaa898cbe44d620a64aab52eec72c8e91d1355b5
RUN apt-get update && apt-get install -y --no-install-recommends python3 unzip && rm -rf /var/lib/apt/lists/* && ln -s /usr/bin/python3 /usr/local/bin/python
COPY --from=compiler /opt/dafny /opt/dafny
COPY z3.whl /tmp/z3.whl
RUN unzip -q /tmp/z3.whl -d /opt/z3 && rm /tmp/z3.whl && find /opt/z3 -name z3 -type f -exec chmod 755 {} \; && ln -s /opt/z3/z3_solver-4.13.0.0.data/data/bin/z3 /usr/local/bin/z3
COPY dafny /usr/local/bin/dafny
RUN chmod 755 /usr/local/bin/dafny && dafny --version && z3 --version
ENV DOTNET_CLI_HOME=/tmp DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
LABEL org.colossus.managed="true" org.colossus.toolchain="dafny-4.11.0-z3-4.13.0"
USER 1000:1000
WORKDIR /work
