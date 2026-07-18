# wit/v0 upstream pin

Vendored from: https://github.com/zeroclaw-labs/zeroclaw-plugins
Commit: 23a5dcb953f697cae08d8e2802b39894ac9ddda1 (2026-07-17)
Last wit/v0 change at that commit: e148f90 "fix(wit): align channel plugin ABI with core host" (2026-07-17)

Synced: 2026-07-18. The realignment touched channel.wit (typed
webhook-rejection), sockets.wit, and ws-client.wit; none of these are
imported by the tool-plugin world these components target. tool.wit,
plugin-info.wit, types.wit, logging.wit, memory.wit, and inbound.wit were
already identical.

Re-verify against upstream and rebuild within 48h of submission:

    git -C ../zeroclaw-plugins pull
    diff -r wit/v0 ../zeroclaw-plugins/wit/v0
