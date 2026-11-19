# SPDX-License-Identifier: EUPL-1.2

# The relay image (PLAN.md §7): one static binary and a CA bundle on scratch,
# with no shell or package manager (S-2, S-3).

ARG VERSION=0.0.0-dev

# The builder runs on the build host's platform and cross-compiles for the
# target, so multi-arch builds need no emulation (S-4). Keep the tag and
# digest on this one line: CI compares the tag with go.mod's toolchain, and
# go-patch.yml updates only this line and go.mod (PLAN.md §12).
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
# GOTOOLCHAIN=local builds with this pinned image's Go rather than
# downloading a toolchain, and GOPROXY=off fails the build if a module
# dependency ever appears (PLAN.md D2). CGO_ENABLED=0 makes the binary static.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
# Symbols stay in: release.yml scans the binary with govulncheck -mode=binary.
RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-X main.version=${VERSION}" -o /out/relay ./cmd/relay

FROM scratch
ARG VERSION
# release.yml adds the source and revision labels, which only a release build
# knows (PLAN.md §12).
LABEL org.opencontainers.image.title="eid-forge-remote" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="EUPL-1.2"
# The CA bundle comes from the builder, so it refreshes with every toolchain
# rebuild (PLAN.md §7, §12).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/relay /relay
USER 65532:65532
# A soft GC target below the 128 MB container limit (PLAN.md §6 R-4).
ENV GOMEMLIMIT=96MiB
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/relay", "healthcheck"]
ENTRYPOINT ["/relay"]
CMD ["serve"]
