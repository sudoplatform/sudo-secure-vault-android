package com.sudoplatform.sudosecurevault

import com.sudoplatform.sudologging.AndroidUtilsLogDriver
import com.sudoplatform.sudologging.LogLevel
import com.sudoplatform.sudologging.Logger

/**
 * Default logger.
 */
class DefaultLogger {

    companion object {
        val instance = Logger("SudoSecureVault", AndroidUtilsLogDriver(LogLevel.INFO))
    }

}