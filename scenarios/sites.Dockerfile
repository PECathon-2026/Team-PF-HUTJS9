# Scenario + red-team pages baked into an unprivileged nginx (owner: WIN).
# Built by compose from scenarios/; requires `make scenarios-build` first.
# Only build/site is copied: the ground truth (build/truth) never enters the image.
FROM nginxinc/nginx-unprivileged:1.27.5-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0
COPY build/site/ /usr/share/nginx/html/
