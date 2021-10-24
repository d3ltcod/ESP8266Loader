/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package esp8266loader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import modulestruct.Header;
import modulestruct.Image;
import modulestruct.Segment;

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class ESP8266LoaderLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		// Name the loader.  This name must match the name of the loader in the .opinion files.
		return "ESP8266 Image";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.

		BinaryReader reader = new BinaryReader(provider, true);
		
		if (reader.length() > 0x1000) {
			var magic = reader.readNextByte();

			if (magic == Constants.ESP_MAGIC_BASE_V1) {
				Msg.info(this, "ESP Magic Matched");
				loadSpecs.add(new LoadSpec(this, 0, 
						 new LanguageCompilerSpecPair("Xtensa:LE:32:default", "default"), true));
			} else throw new IOException("This is not an ESP8266 file");
		}
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Load the bytes from 'provider' into the 'program'.
		BinaryReader reader = new BinaryReader(provider, true);
		Image image = new Image(reader);
		
		
		markupHeader(program, image.getHeader(), monitor, provider.getInputStream(0), log);
		
		try {
			markupSections(program, image, monitor, provider.getInputStream(image.getInitialPos()), log);
		} catch (AddressOverflowException | IOException e) {
			e.printStackTrace();
		}
		
		// Create entry point
		Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(image.getHeader().getEntrypoint(), true);
		program.getSymbolTable().addExternalEntryPoint(entryAddress);
	} 
		

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	private void markupHeader(Program program, Header header, TaskMonitor monitor, InputStream reader, MessageLog log) {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "ESP8266 Header";
		
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
		
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, ".header", start, reader, 8, "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
		} catch (AddressOverflowException e) {
			e.printStackTrace();
		}
	}
	
	private void markupSections(Program program, Image image, TaskMonitor monitor, InputStream reader, MessageLog log) throws AddressOverflowException, IOException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "ESP8266 Section";
		
		for (Segment segment: image.getSegments()) {
			reader.skip(8);
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(segment.getOffset());

			MemoryBlockUtils.createInitializedBlock(program, false,
				segment.getSegmentName(), start, reader, segment.getSize(), "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);

			// Mark code sections
			if(segment.isCode())
			{
				AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
				if (codeProp == null) {
					try {
						codeProp = program.createAddressSetPropertyMap("CodeMap");
					}
					catch (DuplicateNameException e) {
						codeProp = program.getAddressSetPropertyMap("CodeMap");
					}
				}

				if (codeProp != null) {
					codeProp.add(start, start);
				}
			}
			
		}
	}
}
