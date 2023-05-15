package org.nfctools.mf.classic;

import java.io.IOException;

import org.nfctools.api.ApduTag;
import org.nfctools.api.TagInfo;
import org.nfctools.mf.MfConstants;
import org.nfctools.mf.MfException;
import org.nfctools.mf.MfLoginException;
import org.nfctools.mf.block.Block;
import org.nfctools.mf.block.BlockResolver;
import org.nfctools.mf.block.MfBlock;
import org.nfctools.mf.block.TrailerBlock;
import org.nfctools.mf.mad.AbstractMad;
import org.nfctools.mf.mad.ApplicationDirectory;
import org.nfctools.mf.mad.MadConstants;
import org.nfctools.mf.mad.MadKeyConfig;
import org.nfctools.scio.Command;
import org.nfctools.scio.Response;
import org.nfctools.spi.acs.Acs;
import org.nfctools.spi.acs.Apdu;
import org.nfctools.spi.acs.LoginKeyHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TagInfoBestEffortReader implements MfClassicReaderWriter{
	   private Logger logger = LoggerFactory.getLogger(TagInfoBestEffortReader.class); 
	   
		private TagInfo tagInfo;
		private ApduTag apduTag;
		private MemoryLayout memoryLayout;
		private LoginKeyHandler loginKeyHandler = new LoginKeyHandler();

		public TagInfoBestEffortReader(ApduTag apduTag, MemoryLayout memoryLayout) {
			this.apduTag = apduTag;
			this.memoryLayout = memoryLayout;
		}

		@Override
		public MfBlock[] readBlock(MfClassicAccess access) throws IOException {
			byte blockNumber;
			loginIntoSector(access);
			MfBlock[] returnBlocks = new Block[access.getBlocksToRead()];
			for (int currentBlock = 0; currentBlock < access.getBlocksToRead(); currentBlock++) {
				blockNumber = (byte)memoryLayout.getBlockNumber(access.getSector(), access.getBlock() + currentBlock);
				Command readBlock = new Command(Apdu.INS_READ_BINARY, 0x00, blockNumber, 16);
				Response readBlockResponse;
				readBlockResponse = apduTag.transmit(readBlock);
				if (!readBlockResponse.isSuccess()) {
					throw new MfException("Reading block failed. Sector: " + access.getSector() + ", Block: "
							+ access.getBlock() + " Key: " + access.getKeyValue().getKey().name() + ", Response: "
							+ readBlockResponse);
				}
				returnBlocks[currentBlock] = BlockResolver.resolveBlock(memoryLayout, access.getSector(), currentBlock
						+ access.getBlock(), readBlockResponse.getData());
			}
			return returnBlocks;
		}

		@Override
		public void writeBlock(MfClassicAccess access, MfBlock... mfBlock) throws IOException {
			loginIntoSector(access);
			for (int currentBlock = 0; currentBlock < mfBlock.length; currentBlock++) {
				int blockNumber = memoryLayout.getBlockNumber(access.getSector(), access.getBlock()) + currentBlock;
				if (memoryLayout.isTrailerBlock(access.getSector(), access.getBlock() + currentBlock)) {
					if (!(mfBlock[currentBlock] instanceof TrailerBlock))
						throw new MfException("invalid block for trailer");
				}
				Command writeBlock = new Command(Apdu.INS_UPDATE_BINARY, 0x00, blockNumber, mfBlock[currentBlock].getData());
				Response writeBlockResponse;
				writeBlockResponse = apduTag.transmit(writeBlock);
				if (!writeBlockResponse.isSuccess()) {
					throw new MfException("Writing block failed. Sector: " + access.getSector() + ", Block: "
							+ access.getBlock() + " Key: " + access.getKeyValue().getKey().name() + ", Response: "
							+ writeBlockResponse);
				}
			}
		}

		@Override
		public MemoryLayout getMemoryLayout() {
			return memoryLayout;
		}

		protected void loginIntoSector(MfClassicAccess access) throws IOException {
			if (loginKeyHandler.isAlreadyLoggedIn(access)) {
				return;
			}
			int index = loginKeyHandler.getPreviouslyLoadedKeyIndex(access);
			if (index == -1) {
				index = loadAccessKey(access);
			}
			logger.info("key index :{}", index);
			loginIntoSector(access, index);
		}

		/**
		 * The “Load Authentication Keys command” will load the authentication keys into the reader. The authentication keys
		 * are used to authenticate the particular sector of the Mifare 1K/4K Memory Card.
		 * 
		 * @param access
		 * @throws IOException
		 */
		private int loadAccessKey(MfClassicAccess access) throws IOException {
			int memoryKeyId = loginKeyHandler.getNextKeyPosition();
			Command loadKey = new Command(Apdu.INS_EXTERNAL_AUTHENTICATE, Acs.P1_LOAD_KEY_INTO_VOLATILE_MEM, memoryKeyId,
					access.getKeyValue().getKeyValue());
			Response loadKeyResponse = apduTag.transmit(loadKey);
			if (!loadKeyResponse.isSuccess()) {
				throw new MfLoginException("Loading key failed. Sector: " + access.getSector() + ", Block: "
						+ access.getBlock() + " Key: " + access.getKeyValue().getKey().name() + ", Response: "
						+ loadKeyResponse);
			}
			loginKeyHandler.rememberKey(access);
			return memoryKeyId;
		}

		private void loginIntoSector(MfClassicAccess access, int memoryKeyId) throws IOException {
			byte blockNumber = (byte)memoryLayout.getBlockNumber(access.getSector(), access.getBlock());
			byte keyTypeToUse = access.getKeyValue().getKey() == Key.A ? Acs.KEY_A : Acs.KEY_B;
			Command auth = new Command(Apdu.INS_INTERNAL_AUTHENTICATE_ACS, 0, 0, new byte[] { 0x01, 0x00, blockNumber,
					keyTypeToUse, (byte)memoryKeyId });
			Response authResponse = apduTag.transmit(auth);
			if (!authResponse.isSuccess()) {
				//login failed
				try {
					//sleep due to reader response time too slow
					Thread.sleep(1500);
				} catch (InterruptedException e1) {
				}
				loginKeyHandler.resetCurrentKeys();
				throw new MfLoginException("Login failed. Sector: " + access.getSector() + ", Block: " + access.getBlock()
						+ " Key: " + access.getKeyValue().getKey().name() + ", Response: " + authResponse);
			}
			else {
				loginKeyHandler.setSuccessfulLogin(access);
			}
		}

		@Override
		public boolean hasApplicationDirectory() throws IOException {
			try {
				MfClassicAccess access = new MfClassicAccess(MfClassicConstants.MAD_KEY, 0,
						memoryLayout.getTrailerBlockNumberForSector(0));
				TrailerBlock madTrailer = (TrailerBlock)readBlock(access)[0];
				return ((madTrailer.getGeneralPurposeByte() & MadConstants.GPB_MAD_AVAILABLE) != 0);
			}
			catch (MfLoginException e) {
				return false;
			}
		}

		@Override
		public ApplicationDirectory createApplicationDirectory(MadKeyConfig keyConfig) throws IOException {
			return AbstractMad.createInstance(this, keyConfig);
		}

		/**
		 * Returns the application directory in read-only mode. If a write attempt is made on the application directory an
		 * IllegalStateException is thrown. If the card does not have an application directory a MfException is thrown.
		 * 
		 * @param card
		 * @param readerWriter
		 * @throws IOException
		 */
		@Override
		public ApplicationDirectory getApplicationDirectory() throws IOException {
			return getApplicationDirectory(MfConstants.NDEF_KEY_CONFIG);
		}

		/**
		 * Returns the application directory in read-write mode. If the card does not have an application directory a
		 * MfException is thrown.
		 * 
		 * @param card
		 * @param readerWriter
		 * @throws IOException
		 */
		@Override
		public ApplicationDirectory getApplicationDirectory(MadKeyConfig keyConfig) throws IOException {
			return AbstractMad.initInstance(this, keyConfig);
		}

		@Override
		public TagInfo getTagInfo() throws IOException {
//			loadAccessKey(new MfClassicAccess(MfClassicConstants.TRANSPORT_KEY, 0, 0));
//			loadAccessKey(new MfClassicAccess(MfClassicConstants.MAD_KEY, 0, 0));
//			
			if (tagInfo == null) {
				byte[] id = new byte[4];
				//stopping transport key sequence due to factory format using transport key FFFF as default, using this key as default speed up reading tag
				MfBlock[] block = readManuBlockWithMultiKeys(MfClassicConstants.TRANSPORT_KEY,MfClassicConstants.MAD_KEY);
				if (block != null) {
					System.arraycopy(block[0].getData(), 0, id, 0, 4);
					tagInfo = new TagInfo(apduTag.getTagType(), id);
				}
			}
			return tagInfo;
		}

		private MfBlock[] readManuBlockWithMultiKeys(KeyValue... keyValues) throws IOException {
			for (KeyValue keyValue : keyValues) {
				try {
					MfClassicAccess access = new MfClassicAccess(keyValue, 0, 0);
					MfBlock[] block = readBlock(access);
					return block;
				}
				catch (MfLoginException e) {
				}
			}
			return null;
		}
}
