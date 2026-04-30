# `@aegis/guard`

TypeScript client for the [AEGIS](https://github.com/cwellbournewood/aegis) prompt-injection defense gateway.

## Install

```bash
npm install @aegis/guard
```

## Usage

```ts
import { AegisClient, c } from "@aegis/guard";
import Anthropic from "@anthropic-ai/sdk";

const aegis = new AegisClient({ baseUrl: "http://localhost:8080" });

const session = await aegis.createSession({
  userIntent: "summarize my latest invoice email",
  upstream: "anthropic",
});

await session.mintCapability("read_email", {
  constraints: { folder: c.eq("inbox"), limit: c.maxLen(10) },
});

const claude = new Anthropic({ baseURL: session.proxyUrl, apiKey: process.env.ANTHROPIC_API_KEY });

const resp = await claude.messages.create({
  model: "claude-sonnet-4-5",
  max_tokens: 512,
  messages: [{ role: "user", content: "summarize my latest invoice email" }],
  // @ts-expect-error AEGIS extension
  ...session.augmentBody({}),
});
```

## License

Apache-2.0
