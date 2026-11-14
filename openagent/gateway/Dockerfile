FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
ENV NODE_ENV=production
# The runtime executes the already-built gateway with node only. npm,
# corepack, and Yarn add no runtime capability and have repeatedly carried
# HIGH/CRITICAL archive and parser CVEs, so omit those package-manager trees
# from the production image instead of suppressing the scanner findings.
RUN apk upgrade --no-cache && \
    rm -rf \
    /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /opt/yarn-* && \
    rm -f \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack \
    /usr/local/bin/yarn \
    /usr/local/bin/yarnpkg
USER node
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
EXPOSE 6402
CMD ["node", "dist/server.js"]
