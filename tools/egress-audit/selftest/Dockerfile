# One image per fixture product: the shared helpers, the golden statistics report and the
# fixture's own directory.
FROM node:24-alpine
ARG FIXTURE=quiet
WORKDIR /app
COPY package.json ./
COPY lib ./lib
COPY stats-sender/report.json ./lib/stats-report.json
COPY ${FIXTURE} ./fixture
USER node
EXPOSE 8080
CMD ["node", "fixture/server.mjs"]
