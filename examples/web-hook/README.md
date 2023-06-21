# POC (WIP)
## Instruction:
 
- compile sftpgo
    ```bash
    go build -ldflags "-s -w -X github.com/drakkan/sftpgo/v2/pkg/version.commit=`git describe --always --abbrev=8 --dirty` -X github.com/drakkan/sftpgo/v2/pkg/version.date=`date -u +%FT%TZ`" -o sftpgo
    ```

- launch the sftpgo server, use envvars to create the admin user
    ```bash
    SFTPGO_DEFAULT_ADMIN_USERNAME=admin SFTPGO_DEFAULT_ADMIN_PASSWORD=admin ./sftpgo serve --log-level debug
    ```

- browse to `examples/web-hook`
    ```
    cd examples/web-hook
    ```

- lunch the init_hooks.sh
    ```
    chmod +x ./init_hooks.sh && ./init_hooks.sh
    ```

- this script will create demo user and register a new event action and a new event rule. to customize action or rules options, you can manually create/configure it from the web admin UI, or change the vars in the beginning of the script.

- Start the v server that will be listen for sftpgo fs events via simple http endpoint
    ```
    v run .
    ```

- Browse to http://127.0.0.1:8080/web/client/files to start interacting with the web client UI

- Login using the username "demo" and the password "demo"

- try to upload, download or just browse dirs, every process will wait few seconds till the web handler done.

- uploading, downloading and listing dir content via any supported protocol (not only web client UI) would trigger web-hook for pre-* events. any registered fs operation won't carry on before the handler return first.