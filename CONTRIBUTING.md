# Contributing

Thanks for helping improve `wcdscan`.

## Development

```bash
git clone https://github.com/AmpedWasTaken/wcdscan.git
cd wcdscan
go test ./...
go vet ./...
go build ./cmd/wcdscan
```

## Pull requests

Please keep changes focused and include tests when behavior changes.

For new detection logic, describe:

1. the signal being measured;
2. why it indicates cache-deception risk;
3. likely false positives;
4. how the tool should explain the evidence to the user.

The project prioritizes **low false positives and explainable evidence** over request volume.

## Scope

Good contributions include:

- cache/CDN detection;
- reporting;
- CLI UX;
- test fixtures;
- documentation;
- safer authentication handling;
- performance improvements.
