# Remote server image. Configuration comes from environment variables, never from a .env file in the image.
# Both stages use node:24.21.0-alpine3.24, pinned by the digest of its multi-platform index so every build starts from the same image.

FROM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
WORKDIR /app
# Inside a container the server has to listen on every interface to be reachable through the published port. So it
# refuses to start without MCP_PUBLIC_URL: the default public URL is on localhost, whose relaxed settings (plain http,
# FO_INSECURE_TLS, direct tokens of FO_CLIENT_ID) are only safe on one machine. For a local docker run set
# MCP_PUBLIC_URL=http://localhost:3000/mcp and publish the port on the loopback address only, -p 127.0.0.1:3000:3000.
ENV NODE_ENV=production MCP_PORT=3000 MCP_HOST=0.0.0.0
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
EXPOSE 3000
USER node
CMD ["node", "dist/http.js"]
