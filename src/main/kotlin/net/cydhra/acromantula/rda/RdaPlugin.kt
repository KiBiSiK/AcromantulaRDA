package net.cydhra.acromantula.rda

import net.cydhra.acromantula.features.importer.ImporterFeature
import net.cydhra.acromantula.plugins.AcromantulaPlugin
import org.apache.logging.log4j.LogManager

class RdaPlugin : AcromantulaPlugin {

    companion object {
        private val logger = LogManager.getLogger()
    }

    override val author: String = "Cydhra"

    override val name: String = "Anno 1701 RDA Parsers"

    override fun initialize() {
        ImporterFeature.registerImporterStrategy(Rda1Importer())
        logger.info("registered rda parsers")
    }

}