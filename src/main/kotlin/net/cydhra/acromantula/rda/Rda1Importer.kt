package net.cydhra.acromantula.rda

import net.cydhra.acromantula.features.importer.ImporterStrategy
import net.cydhra.acromantula.features.util.FileTreeBuilder
import net.cydhra.acromantula.workspace.WorkspaceService
import net.cydhra.acromantula.workspace.filesystem.FileEntity
import org.apache.logging.log4j.LogManager
import java.io.PushbackInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset
import java.util.zip.Inflater
import kotlin.experimental.xor

class Rda1Importer : ImporterStrategy {
    companion object {
        private const val RDA_HEADER_SIZE = 260
        private const val RDA_MAGIC_SIZE = 26
        private const val FILE_HEADER_SIZE = 276

        private val logger = LogManager.getLogger()
    }

    override fun handles(fileName: String, fileContent: PushbackInputStream): Boolean {
        val headerBuffer = ByteArray(RDA_HEADER_SIZE)
        val readBytes = fileContent.read(headerBuffer, 0, RDA_HEADER_SIZE)
        fileContent.unread(headerBuffer.copyOfRange(0, readBytes))

        deobfuscateRdaBlock(headerBuffer)

        if (readBytes < RDA_HEADER_SIZE)
            return false

        // check for magic string
        if (String(
                headerBuffer.sliceArray(0 until RDA_MAGIC_SIZE),
                Charset.forName("UTF-8")
            ) == "Crypted Resource File V1.1"
        )
            return true

        return false

    }

    override fun import(parent: FileEntity?, fileName: String, fileContent: PushbackInputStream) {
        val fileBuffer = fileContent.readAllBytes()
        val headerBuffer = fileBuffer.sliceArray(0 until RDA_HEADER_SIZE)
        deobfuscateRdaBlock(headerBuffer)

        logger.trace("importing RDA file")

        // generate archive entry
        val archiveEntity = WorkspaceService.addArchiveEntry(fileName, parent)
        val treeBuilder = FileTreeBuilder(archiveEntity)

        // extract file count
        val fileCount = ByteBuffer.wrap(headerBuffer.sliceArray((RDA_HEADER_SIZE - 4) until RDA_HEADER_SIZE))
            .order(ByteOrder.LITTLE_ENDIAN)
            .getInt(0)
        logger.trace("file count: $fileCount")

        // extract file headers
        val dictionary = fileBuffer.sliceArray(RDA_HEADER_SIZE until RDA_HEADER_SIZE + fileCount * FILE_HEADER_SIZE)
        deobfuscateRdaBlock(dictionary)

        val inflater = Inflater()

        // construct archive tree
        for (i in (0 until fileCount)) {
            // read current dictionary entry
            val dictionaryEntryContent =
                dictionary.sliceArray((i * FILE_HEADER_SIZE) until ((i + 1) * FILE_HEADER_SIZE))
            val dictionaryEntry = RdaDictionaryEntry(dictionaryEntryContent)

            // extract file name and insert parent directories
            val parentDirectory = treeBuilder.getParentDirectory(dictionaryEntry.filename)
            val parentDirName = treeBuilder.getParentPath(dictionaryEntry.filename)
            val simpleName = dictionaryEntry.filename.removePrefix(parentDirName)

            // read and decompress file entry
            val archiveFileContent: ByteArray
            if (dictionaryEntry.compressionFlag == 7) {
                archiveFileContent = ByteArray(dictionaryEntry.decompressedFileSize)
                val compressedContent =
                    fileBuffer.sliceArray(
                        dictionaryEntry.offset until dictionaryEntry.offset + dictionaryEntry.compressedFileSize
                    )

                inflater.reset()
                inflater.setInput(compressedContent)
                inflater.inflate(archiveFileContent)
            } else {
                archiveFileContent = fileBuffer.sliceArray(
                    dictionaryEntry.offset until dictionaryEntry.offset + dictionaryEntry.decompressedFileSize
                )
            }

            WorkspaceService.addFileEntry(simpleName, parentDirectory, archiveFileContent)
        }
    }

    /**
     * Decrypt an RDA archive block. The header and the dictionary block are obfuscated using a key-less stream
     * scrambler algorithm. This method can deobfuscate the headers by reverting the algorithm. Since the algorithm has
     * a state during execution, the full block without any additional padding must be the argument. The buffer is
     * descrambled in-place
     *
     * @param buffer the whole block that shall be deobfuscated.
     */
    private fun deobfuscateRdaBlock(buffer: ByteArray) {
        var keyState = 666666

        for (i in (0 until (buffer.size / 2))) {
            var key: Int = keyState * 0x343FD + 0x269EC3
            keyState = key
            key = (key shr 16) and 0x7FFF

            // the key is interpreted as a 16-bit-word, therefore two bytes are decrypted at once
            buffer[i * 2] = buffer[i * 2] xor (key and 0xFF).toByte()
            buffer[i * 2 + 1] = buffer[i * 2 + 1] xor ((key ushr 8) and 0xFF).toByte()
        }
    }

    /**
     * A parsed structure of a single dictionary entry of an RDA archive. Takes the byte array of the entry and
     * parses it into the structure
     *
     * @param block the entry content
     */
    private class RdaDictionaryEntry(block: ByteArray) {
        val filename: String
        val offset: Int
        val compressedFileSize: Int
        val decompressedFileSize: Int
        val compressionFlag: Int
        val timestamp: Int

        init {
            filename = String(block.sliceArray(0..255), Charset.forName("UTF-8"))
            with(ByteBuffer.wrap(block.sliceArray(256 until block.size)).order(ByteOrder.LITTLE_ENDIAN)) {
                offset = getInt(0)
                compressedFileSize = getInt(4)
                decompressedFileSize = getInt(8)
                compressionFlag = getInt(12)
                timestamp = getInt(16)
            }
        }

        override fun toString(): String {
            return "RdaDictionaryEntry(filename='$filename', offset=$offset, compressedFileSize=$compressedFileSize, decompressedFileSize=$decompressedFileSize, compressionFlag=$compressionFlag, timestamp=$timestamp)"
        }
    }
}