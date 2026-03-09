---
name: NestJS Security
description: >
  Activate when writing or reviewing NestJS code involving APP_GUARD/Guard bypass, ValidationPipe
  whitelist/mass assignment, class-transformer prototype pollution (CVE-2022-21190),
  class-validator ReDoS (CVE-2023-26115), @nestjs/passport JwtStrategy alg:none/ignoreExpiration,
  RolesGuard RBAC, TypeORM/Prisma raw SQL injection, ConfigModule secret leaks,
  CORS misconfiguration, @nestjs/throttler rate limiting, multer file upload validation,
  HttpModule SSRF, ClassSerializerInterceptor sensitive field exposure, WebSocket WsGuard,
  microservice transport TLS (RabbitMQ/Redis), GraphQL depth/complexity limits, ExceptionFilter
  stack trace exposure. Also activate when user mentions APP_INTERCEPTOR, APP_PIPE,
  @nestjs/jwt, nestjs/axios, TypeORM, Prisma, graphql-depth-limit, or asks for a NestJS security review.
---

## Use this skill when

Activate when writing or reviewing NestJS code involving APP_GUARD/Guard bypass, ValidationPipe
whitelist/mass assignment, class-transformer prototype pollution (CVE-2022-21190),
class-validator ReDoS (CVE-2023-26115), @nestjs/passport JwtStrategy alg:none/ignoreExpiration,
RolesGuard RBAC, TypeORM/Prisma raw SQL injection, ConfigModule secret leaks,
CORS misconfiguration, @nestjs/throttler rate limiting, multer file upload validation,
HttpModule SSRF, ClassSerializerInterceptor sensitive field exposure, WebSocket WsGuard,
microservice transport TLS (RabbitMQ/Redis), GraphQL depth/complexity limits, ExceptionFilter
stack trace exposure. Also activate when user mentions APP_INTERCEPTOR, APP_PIPE,
@nestjs/jwt, nestjs/axios, TypeORM, Prisma, graphql-depth-limit, or asks for a NestJS security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
