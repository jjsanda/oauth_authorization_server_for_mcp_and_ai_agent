# Multi-stage build shared by all three binaries; pick one with
#   --build-arg COMPONENT=authserver|resourceserver|agent
FROM golang:1.22 AS build
ARG COMPONENT
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app "./cmd/${COMPONENT}"

# Distroless static: no shell, no package manager, tiny attack surface.
# Health checks use the binary's own -healthcheck self-probe because there is
# no curl or wget in this image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot
ENTRYPOINT ["/app"]
