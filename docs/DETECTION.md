# Detection model

`wcdscan` is intentionally evidence-first. It does not classify a target as suspicious solely because a cache header exists.

## Baseline phase

Two requests are compared:

1. authenticated request to the original endpoint;
2. anonymous request to the same endpoint.

If these are identical, the endpoint may not be meaningfully personalized, so cache-deception conclusions are weaker.

## Variant phase

The scanner requests static-looking path variants while authenticated, then repeats the exact same variant anonymously.

For each response it records:

- status code;
- body length;
- SHA-256 body hash;
- cache indicators;
- policy warnings.

Response bodies are not printed.

## High-confidence signal

A finding is classified as high/suspicious when all three conditions hold:

```text
A. authenticated baseline differs from anonymous baseline
B. every anonymous confirmation matches the authenticated variant
C. at least one anonymous confirmation shows shared-cache evidence
```

This is stronger than checking `.css` handling or `CF-Cache-Status` alone.

## Caveats

A scanner result is still a lead, not mathematical proof. Reverse proxies, authentication gateways, A/B testing, bot protection, and personalized edge logic can all affect results.

Validate findings manually with a dedicated test account.
