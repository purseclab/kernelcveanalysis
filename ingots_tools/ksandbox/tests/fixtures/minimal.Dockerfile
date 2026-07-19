FROM busybox:1.37.0-musl

ENTRYPOINT ["/bin/sh", "-c", "echo original-entrypoint-ran; exit 99"]
CMD ["original-cmd"]
