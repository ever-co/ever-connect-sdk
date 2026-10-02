# One image per fixture product: the shared helpers and the fixture's own directory.
FROM node:24-alpine
ARG FIXTURE=quiet
WORKDIR /app
COPY package.json ./
COPY lib ./lib
COPY ${FIXTURE} ./fixture
USER node
EXPOSE 8080
CMD ["node", "fixture/server.mjs"]
