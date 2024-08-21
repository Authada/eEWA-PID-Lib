# eEWA PID Lib

The eEWA PID Lib handles the communication with the "eEWA Applet" installed on a Secure Element or eSIM
and can be integrated into an Android app. The artifact is in form of an AAR.

## Key features
- communicate with the eEWA applet with android.se.omapi with the main component `PidLib` of the eEWA PID Lib.
- provides interfaces for easy integration into an app
- send commands to eEWA applet needed during issuing and presentation process
- supports specific commands like one which requests garbage collection on eEWA applet (handle with care!)

## How to use

To integrate the eEWA PID Lib, add the following to the build.gradle.kts of your app module:

```kotlin
dependencies {
    implementation("de.authada.eewa:eewa-pid-lib:1.0")
}
```

The `SecureElementCallback` interface has to be implemented in your MainActivity. With this interface, the result of the communication establishment with the Secure Element can be handled.

```kotlin
interface SecureElementCallback {
    fun onConnected()
    fun onConnectionCouldntBeEstablished(error: String)
}
```

Following a sample code to initialize the eEWA PID Lib in the MainActivity with a composable to display text:

```kotlin
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import de.authada.eewa.secure_element.SecureElementCallback
import de.authada.eewa.secure_element.SecureElementWrapper
import de.authada.eewa.wallet.PidLib

val statusText = mutableStateOf("statusText")
class MainActivity : ComponentActivity(), SecureElementCallback {

    private lateinit var pidLib: PidLib
    private var secureElementWrapper: SecureElementWrapper = SecureElementWrapper(this)

    private fun init(secureElementWrapper: SecureElementWrapper) {
        pidLib = PidLib(secureElementWrapper)
        secureElementWrapper.init(this)
    }

    override fun onDestroy() {
        super.onDestroy()
        pidLib.onDestroy()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            Column {
                Button(content = {
                    Text(text = "Init Secure Element connection")
                }, onClick = {
                    if (!::pidLib.isInitialized) {
                        init(secureElementWrapper)
                    }
                })
                log()
            }
        }
    }

    override fun onConnected() {
        statusText.value = "Connection established"
    }


    override fun onConnectionCouldntBeEstablished(error: String) {
        statusText.value = "Connection couldn't be established! Error: $error"
    }
}

@Composable
fun log() {
    val myText by statusText
    Text(
        myText, modifier = Modifier.verticalScroll(rememberScrollState())
    )
}
```






