pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Caelestia.Config
import qs.components
import qs.components.controls
import qs.services

Item {
    id: root

    property string vaultStatus: "loading"
    property string userEmail: ""
    property string serverUrl: ""
    property string message: ""
    property var allItems: []
    property var items: []
    property bool itemsLoaded: false
    property int timeoutMinutes: 15
    property bool persistSession: false
    property int expiresInSeconds: 0
    property bool debugBroker: false

    readonly property string configHome: Quickshell.env("XDG_CONFIG_HOME") || Quickshell.env("HOME") + "/.config"
    readonly property string helper: configHome + "/quickshell/caelestia/scripts/caelestia-vault"
    readonly property bool unlocked: vaultStatus === "unlocked"

    implicitWidth: 840
    implicitHeight: 500

    function refreshStatus(): void {
        if (!statusProc.running)
            statusProc.running = true;
    }

    function loadItems(force: bool): void {
        if (!root.unlocked || listProc.running || (root.itemsLoaded && !force))
            return;
        root.message = "Loading vault items...";
        listProc.errorText = "";
        listProc.command = force ? [root.helper, "list", "--refresh"] : [root.helper, "list"];
        listProc.startedAt = Date.now();
        listProc.running = true;
    }

    function applyFilter(): void {
        const query = searchField.text.trim().toLocaleLowerCase();
        if (!query) {
            root.items = root.allItems;
        } else {
            root.items = root.allItems.filter(item =>
                (item.name || "").toLocaleLowerCase().includes(query)
                || (item.username || "").toLocaleLowerCase().includes(query)
                || (item.uri || "").toLocaleLowerCase().includes(query));
        }
        if (root.itemsLoaded) {
            const visibleLabel = `${root.items.length} ${root.items.length === 1 ? "item" : "items"}`;
            const totalLabel = `${root.allItems.length} ${root.allItems.length === 1 ? "item" : "items"}`;
            root.message = query ? `${visibleLabel} of ${totalLabel}` : `${totalLabel} in the vault`;
        }
    }

    function runAction(args: list<string>, successMessage: string): void {
        if (actionProc.running)
            return;
        if ((args[0] || "").startsWith("copy-"))
            root.message = "Retrieving the value from Bitwarden...";
        actionProc.successMessage = successMessage;
        actionProc.actionName = args[0] || "";
        actionProc.command = [root.helper].concat(args);
        actionProc.startedAt = Date.now();
        actionProc.running = true;
    }

    function queueSettingsSave(): void {
        settingsSave.restart();
    }

    function timeoutDescription(): string {
        if (root.timeoutMinutes === 0)
            return "Automatic lock disabled";
        if (root.unlocked && root.expiresInSeconds > 0) {
            const remaining = Math.max(1, Math.ceil(root.expiresInSeconds / 60));
            return `Locks after ${root.timeoutMinutes} min of inactivity (${remaining} min remaining)`;
        }
        return `Locks after ${root.timeoutMinutes} min of inactivity`;
    }

    Component.onCompleted: refreshStatus()

    Process {
        id: statusProc
        command: [root.helper, "status"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const data = JSON.parse(text || "{}");
                    root.vaultStatus = data.status || "error";
                    root.userEmail = data.userEmail || "";
                    root.serverUrl = data.serverUrl || "";
                    root.timeoutMinutes = data.timeoutMinutes ?? 15;
                    root.persistSession = data.persist ?? false;
                    root.expiresInSeconds = data.expiresInSeconds ?? 0;
                    root.debugBroker = data.debug ?? false;
                    if (root.unlocked) {
                        root.loadItems(false);
                    } else {
                        root.allItems = [];
                        root.items = [];
                        root.itemsLoaded = false;
                    }
                } catch (error) {
                    console.warn(`[caelestia-vault] event=status_parse_failed error=${error} response_bytes=${text.length}`);
                    root.vaultStatus = "error";
                    root.message = "Could not reach Bitwarden";
                }
            }
        }
    }

    Process {
        id: listProc
        property string errorText: ""
        property double startedAt: 0
        command: [root.helper, "list"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const data = JSON.parse(text || "[]");
                    if (data.error) {
                        root.allItems = [];
                        root.items = [];
                        root.message = data.error;
                    } else {
                        root.allItems = data;
                        root.itemsLoaded = true;
                        root.applyFilter();
                        searchField.forceActiveFocus();
                    }
                } catch (error) {
                    console.warn(`[caelestia-vault] event=list_parse_failed duration_ms=${Date.now() - listProc.startedAt} error=${error} stdout_bytes=${text.length} stderr_bytes=${listProc.errorText.length}`);
                    root.allItems = [];
                    root.items = [];
                    root.message = listProc.errorText || "Could not read the vault response";
                }
            }
        }
        stderr: StdioCollector {
            onStreamFinished: listProc.errorText = text.trim()
        }
        onExited: {
            if (root.debugBroker)
                console.info(`[caelestia-vault] event=list_process_exited duration_ms=${Date.now() - listProc.startedAt} stderr_bytes=${listProc.errorText.length}`);
            root.refreshStatus();
        }
    }

    Process {
        id: actionProc
        property string successMessage: ""
        property string actionName: ""
        property double startedAt: 0
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const data = JSON.parse(text || "{}");
                    root.message = data.error || actionProc.successMessage;
                } catch (error) {
                    console.warn(`[caelestia-vault] event=action_parse_failed action=${actionProc.actionName} duration_ms=${Date.now() - actionProc.startedAt} error=${error} response_bytes=${text.length}`);
                    if (actionProc.successMessage)
                        root.message = actionProc.successMessage;
                }
            }
        }
        onExited: {
            if (root.debugBroker)
                console.info(`[caelestia-vault] event=action_process_exited action=${actionName} duration_ms=${Date.now() - actionProc.startedAt}`);
            if (actionName === "lock") {
                root.vaultStatus = "locked";
                root.allItems = [];
                root.items = [];
                root.itemsLoaded = false;
            } else if (actionName === "sync") {
                root.itemsLoaded = false;
                root.loadItems(true);
            }
            root.refreshStatus();
            statusRefresh.restart();
        }
    }

    Timer {
        id: statusRefresh
        interval: 1200
        onTriggered: root.refreshStatus()
    }

    Timer {
        id: settingsSave
        interval: 350
        onTriggered: {
            if (actionProc.running) {
                restart();
                return;
            }
            root.runAction(["configure", root.timeoutMinutes.toString(), root.persistSession.toString()], "Vault settings saved");
        }
    }

    Timer {
        interval: 1000
        repeat: true
        running: root.visible
        onTriggered: root.refreshStatus()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Tokens.spacing.medium

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: Tokens.padding.medium
            Layout.rightMargin: Tokens.padding.medium
            spacing: Tokens.spacing.medium

            StyledRect {
                implicitWidth: 50
                implicitHeight: 50
                radius: Tokens.rounding.large
                color: Colours.tPalette.m3primaryContainer

                MaterialIcon {
                    anchors.centerIn: parent
                    text: root.unlocked ? "shield_lock" : "lock"
                    fill: root.unlocked ? 1 : 0
                    color: Colours.palette.m3onPrimaryContainer
                    fontStyle: Tokens.font.icon.extraLarge
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1

                StyledText {
                    text: "Bitwarden"
                    font: Tokens.font.title.large
                    color: Colours.palette.m3onSurface
                }
                StyledText {
                    text: {
                        if (root.vaultStatus === "missing") return "Install Bitwarden CLI to use the vault";
                        if (root.unlocked) return root.userEmail || "Vault unlocked";
                        if (root.vaultStatus === "unauthenticated") return "Sign in to connect";
                        return "Vault locked";
                    }
                    font: Tokens.font.body.small
                    color: root.unlocked ? Colours.palette.m3primary : Colours.palette.m3onSurfaceVariant
                }
            }

            IconTextButton {
                icon: root.unlocked ? "sync" : "lock_open"
                text: root.unlocked ? "Sync" : "Connect"
                disabled: actionProc.running
                onClicked: {
                    if (root.unlocked)
                        root.runAction(["sync"], "Vault synced");
                    else {
                        root.runAction(["unlock"], "Finish signing in from the terminal");
                        statusRefresh.interval = 2500;
                        statusRefresh.restart();
                    }
                }
            }

            IconTextButton {
                icon: "open_in_new"
                text: "Open app"
                onClicked: root.runAction(["open-app"], "Opened Bitwarden")
            }

            IconTextButton {
                visible: root.unlocked
                icon: "lock"
                text: "Lock"
                onClicked: {
                    root.vaultStatus = "locked";
                    root.allItems = [];
                    root.items = [];
                    root.itemsLoaded = false;
                    root.runAction(["lock"], "Vault locked");
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Tokens.spacing.small

            StyledTextField {
                id: searchField
                Layout.fillWidth: true
                placeholderText: "Search logins, sites, or apps"
                leadingIcon: "search"
                enabled: root.unlocked && root.itemsLoaded
                onTextChanged: root.applyFilter()
            }
        }

        StyledRect {
            Layout.fillWidth: true
            implicitHeight: settingsRow.implicitHeight + Tokens.padding.extraSmall * 2
            radius: Tokens.rounding.medium
            color: Colours.tPalette.m3surfaceContainer

            RowLayout {
                id: settingsRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Tokens.padding.small
                anchors.rightMargin: Tokens.padding.small
                spacing: Tokens.spacing.small

                RowLayout {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    spacing: Tokens.spacing.small

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        StyledText {
                            Layout.fillWidth: true
                            text: "Session timeout"
                            elide: Text.ElideRight
                            font: Tokens.font.body.medium
                            color: Colours.palette.m3onSurface
                        }
                        StyledText {
                            Layout.fillWidth: true
                            text: root.timeoutDescription()
                            elide: Text.ElideRight
                            font: Tokens.font.body.small
                            color: Colours.palette.m3onSurfaceVariant
                        }
                    }

                    StyledSpinBox {
                        id: timeoutSpin
                        from: 0
                        to: 525600
                        stepSize: 1
                        value: root.timeoutMinutes
                        onValueModified: {
                            root.timeoutMinutes = Math.round(value);
                            root.queueSettingsSave();
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    spacing: Tokens.spacing.small

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        StyledText {
                            Layout.fillWidth: true
                            text: "Persist after restart"
                            elide: Text.ElideRight
                            font: Tokens.font.body.medium
                            color: Colours.palette.m3onSurface
                        }
                        StyledText {
                            Layout.fillWidth: true
                            text: root.persistSession ? "Stored in GNOME Keyring" : "Kept only in broker memory"
                            elide: Text.ElideRight
                            font: Tokens.font.body.small
                            color: root.persistSession ? Colours.palette.m3error : Colours.palette.m3onSurfaceVariant
                        }
                    }

                    StyledSwitch {
                        checked: root.persistSession
                        onToggled: {
                            root.persistSession = checked;
                            root.queueSettingsSave();
                        }
                    }
                }
            }
        }

        StyledText {
            Layout.fillWidth: true
            Layout.leftMargin: Tokens.padding.small
            text: root.message || (root.unlocked ? "Passwords are fetched only when copied and are never cached on disk." : "Unlock to start an in-memory vault session.")
            font: Tokens.font.body.small
            color: Colours.palette.m3onSurfaceVariant
        }

        StyledRect {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: Tokens.rounding.large
            color: Colours.tPalette.m3surfaceContainer

            StyledText {
                anchors.centerIn: parent
                visible: root.items.length === 0
                text: {
                    if (!root.unlocked) return "Connect and unlock Bitwarden";
                    if (listProc.running) return "Loading vault items...";
                    if (root.itemsLoaded && searchField.text) return "No matching items";
                    return "No logins found";
                }
                font: Tokens.font.body.medium
                color: Colours.palette.m3onSurfaceVariant
            }

            ListView {
                anchors.fill: parent
                anchors.margins: Tokens.padding.medium
                clip: true
                visible: root.items.length > 0
                model: root.items
                spacing: Tokens.spacing.small
                boundsBehavior: Flickable.StopAtBounds

                delegate: StyledRect {
                    id: itemCard
                    required property var modelData

                    width: ListView.view.width
                    implicitHeight: itemRow.implicitHeight + Tokens.padding.small * 2
                    radius: Tokens.rounding.medium
                    color: Colours.tPalette.m3surfaceContainerHigh

                    RowLayout {
                        id: itemRow
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: Tokens.padding.medium
                        anchors.rightMargin: Tokens.padding.medium
                        spacing: Tokens.spacing.medium

                        MaterialIcon {
                            text: itemCard.modelData.passkeys > 0 ? "passkey" : "key"
                            color: Colours.palette.m3primary
                            fontStyle: Tokens.font.icon.large
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            StyledText {
                                Layout.fillWidth: true
                                text: itemCard.modelData.name || "Untitled"
                                elide: Text.ElideRight
                                font: Tokens.font.body.builders.medium.weight(Font.DemiBold).build()
                                color: Colours.palette.m3onSurface
                            }
                            StyledText {
                                Layout.fillWidth: true
                                text: itemCard.modelData.username || itemCard.modelData.uri || "Login"
                                elide: Text.ElideRight
                                font: Tokens.font.body.small
                                color: Colours.palette.m3onSurfaceVariant
                            }
                        }

                        IconTextButton {
                            visible: !!itemCard.modelData.username
                            disabled: actionProc.running
                            icon: "person"
                            text: "Username"
                            horizontalPadding: Tokens.padding.small
                            verticalPadding: Tokens.padding.extraSmall
                            onClicked: root.runAction(["copy-username", itemCard.modelData.id], "Username copied for 30 seconds")
                        }
                        IconTextButton {
                            visible: itemCard.modelData.hasPassword
                            disabled: actionProc.running
                            icon: "password"
                            text: "Password"
                            horizontalPadding: Tokens.padding.small
                            verticalPadding: Tokens.padding.extraSmall
                            onClicked: root.runAction(["copy-password", itemCard.modelData.id], "Password copied for 30 seconds")
                        }
                        IconTextButton {
                            visible: itemCard.modelData.hasTotp
                            disabled: actionProc.running
                            icon: "timer"
                            text: "TOTP"
                            horizontalPadding: Tokens.padding.small
                            verticalPadding: Tokens.padding.extraSmall
                            onClicked: root.runAction(["copy-totp", itemCard.modelData.id], "Code copied for 30 seconds")
                        }
                        IconTextButton {
                            visible: !!itemCard.modelData.uri
                            icon: "open_in_new"
                            text: "Site"
                            horizontalPadding: Tokens.padding.small
                            verticalPadding: Tokens.padding.extraSmall
                            onClicked: root.runAction(["open-uri", itemCard.modelData.id], "Opened site")
                        }
                    }
                }
            }
        }

        StyledRect {
            Layout.fillWidth: true
            implicitHeight: passkeyRow.implicitHeight + Tokens.padding.small * 2
            radius: Tokens.rounding.large
            color: Colours.tPalette.m3tertiaryContainer

            RowLayout {
                id: passkeyRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Tokens.padding.medium
                anchors.rightMargin: Tokens.padding.medium
                spacing: Tokens.spacing.small

                MaterialIcon {
                    text: "passkey"
                    color: Colours.palette.m3onTertiaryContainer
                    fontStyle: Tokens.font.icon.medium
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    spacing: 0
                    StyledText {
                        Layout.fillWidth: true
                        text: "Passkeys"
                        font: Tokens.font.body.builders.small.weight(Font.DemiBold).build()
                        color: Colours.palette.m3onTertiaryContainer
                    }
                    StyledText {
                        Layout.fillWidth: true
                        text: "Use Bitwarden's browser extension. Passkeys stay out of the clipboard."
                        font: Tokens.font.body.small
                        color: Colours.palette.m3onTertiaryContainer
                        elide: Text.ElideRight
                    }
                }
                IconTextButton {
                    icon: "extension"
                    text: "Extension"
                    horizontalPadding: Tokens.padding.small
                    verticalPadding: Tokens.padding.extraSmall
                    onClicked: root.runAction(["browser-extension"], "Opened the extension page")
                }
            }
        }
    }
}
