import QtQuick
import Caelestia.Config
import qs.components
import qs.components.effects
import qs.services
import qs.utils

Item {
    id: root

    implicitWidth: Math.round(Tokens.font.body.large.pointSize * 1.2)
    implicitHeight: Math.round(Tokens.font.body.large.pointSize * 1.2)

    MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.LeftButton | Qt.RightButton
        cursorShape: Qt.PointingHandCursor
        onClicked: mouse => {
            const screenState = ShellState.forActive();
            if (mouse.button === Qt.RightButton) {
                const vaultTab = [
                    Config.dashboard.showDashboard,
                    Config.dashboard.showMedia,
                    Config.dashboard.showPerformance,
                    Config.dashboard.showWeather
                ].filter(value => value).length;
                screenState.dashboardTab = vaultTab;
                screenState.dashboard = true;
            } else {
                screenState.launcher = !screenState.launcher;
            }
        }
    }

    Loader {
        asynchronous: true
        anchors.centerIn: parent
        sourceComponent: SysInfo.isDefaultLogo ? caelestiaLogo : distroIcon
    }

    Component {
        id: caelestiaLogo

        Logo {
            implicitWidth: Math.round(Tokens.font.body.large.pointSize * 1.6)
            implicitHeight: Math.round(Tokens.font.body.large.pointSize * 1.6)
        }
    }

    Component {
        id: distroIcon

        ColouredIcon {
            source: SysInfo.osLogo
            implicitSize: Math.round(Tokens.font.body.large.pointSize * 1.2)
            colour: Colours.palette.m3tertiary
        }
    }
}
