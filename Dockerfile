# Base Stage
FROM node:lts-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Build Stage
FROM base AS builder
WORKDIR /app

# copy configs and src
COPY package.json pnpm-lock.yaml tsconfig.json ./
COPY src src

# install dependencies
RUN pnpm install --frozen-lockfile

# build
RUN pnpm run build
RUN pnpm prune --prod

# Production stage
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production

COPY package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

RUN mkdir targets

CMD ["pnpm", "start"]