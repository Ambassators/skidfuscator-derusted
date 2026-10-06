package dev.skidfuscator.nativetoolchain;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

/** HTTPS transport with redirects disabled; file URIs are supported for offline mirrors and tests. */
public final class HttpsToolchainTransport implements ToolchainTransport {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration REQUEST_TIMEOUT = Duration.ofMinutes(5);
    private HttpClient client;

    public HttpsToolchainTransport() {
        // File mirrors and authenticated cache operations must not initialize
        // network selectors, sockets, or HTTP worker threads.
    }

    private synchronized HttpClient client() {
        if (client == null) {
            client = HttpClient.newBuilder()
                    .connectTimeout(CONNECT_TIMEOUT)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        }
        return client;
    }

    HttpsToolchainTransport(final HttpClient client) {
        this.client = Objects.requireNonNull(client, "client");
    }

    @Override
    public InputStream open(final URI uri, final long maximumBytes) throws IOException {
        validateUri(uri);
        if (maximumBytes <= 0) {
            throw new IllegalArgumentException("maximumBytes must be positive");
        }
        if (uri.getScheme().equalsIgnoreCase("file")) {
            final Path path = Path.of(uri);
            final long size = Files.size(path);
            if (size > maximumBytes) {
                throw new IOException("Toolchain resource exceeds the size limit");
            }
            return Files.newInputStream(path);
        }
        final HttpRequest request = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/octet-stream")
                .build();
        final HttpResponse<InputStream> response;
        try {
            response = client().send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (final InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while downloading SkidLLVM", interrupted);
        }
        if (response.statusCode() != 200) {
            response.body().close();
            throw new IOException("SkidLLVM download returned HTTP " + response.statusCode());
        }
        final var contentLength = response.headers().firstValueAsLong("Content-Length");
        if (contentLength.isPresent() && contentLength.getAsLong() > maximumBytes) {
            response.body().close();
            throw new IOException("Toolchain resource exceeds the size limit");
        }
        return response.body();
    }

    static void validateUri(final URI uri) {
        Objects.requireNonNull(uri, "uri");
        final String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("Toolchain resource URI must be absolute");
        }
        final String normalized = scheme.toLowerCase(Locale.ROOT);
        if (!normalized.equals("https") && !normalized.equals("file")) {
            throw new IllegalArgumentException("Toolchain resources must use HTTPS or file URIs");
        }
        if (uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Toolchain resource URI contains forbidden components");
        }
        if (normalized.equals("https") && (uri.getHost() == null || uri.getHost().isBlank())) {
            throw new IllegalArgumentException("HTTPS toolchain URI has no host");
        }
    }
}
