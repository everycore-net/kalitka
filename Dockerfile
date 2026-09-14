# Build and runtime in one file; the result is a small image that runs as a
# non-root user. Kalitka sits in the HTTP request path and needs nothing from
# the host: no Docker socket, no SSH key, no volumes beyond its own state.
FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src
# Kalitka references the shared Kalitka.Text lib (../Kalitka.Text) — copy both csprojs so restore
# resolves the project reference, then both sources, keeping the relative path intact.
COPY src/Kalitka.Text/Kalitka.Text.csproj ./Kalitka.Text/
COPY src/Kalitka/Kalitka.csproj ./Kalitka/
RUN dotnet restore Kalitka/Kalitka.csproj
COPY src/Kalitka.Text/ ./Kalitka.Text/
COPY src/Kalitka/ ./Kalitka/
RUN dotnet publish Kalitka/Kalitka.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine
WORKDIR /app
COPY --from=build /app .

# State lives here: lists, which hosts are armed, runtime settings.
RUN mkdir -p /data && chown $APP_UID:$APP_UID /data
VOLUME /data
USER $APP_UID

EXPOSE 8080
ENTRYPOINT ["dotnet", "Kalitka.dll"]
