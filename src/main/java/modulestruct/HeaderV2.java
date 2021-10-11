package modulestruct;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class HeaderV2 implements StructConverter{
	
	private byte magic_1;
	private byte magic_2;
	private short config;
	private long entrypoint;
	private long unused;
	private long iromTextSegmentLength;

	
	public HeaderV2(byte magic_1, byte magic_2, short config, long entrypoint, long unused,
			long iromTextSegmentLength) {
		super();
		this.magic_1 = magic_1;
		this.magic_2 = magic_2;
		this.config = config;
		this.entrypoint = entrypoint;
		this.unused = unused;
		this.iromTextSegmentLength = iromTextSegmentLength;
	}

	public byte getMagic_1() {
		return magic_1;
	}


	public byte getMagic_2() {
		return magic_2;
	}


	public short getConfig() {
		return config;
	}


	public long getEntrypoint() {
		return entrypoint;
	}


	public long getIromTextSegmentLength() {
		return iromTextSegmentLength;
	}


	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item_2", 0);
		
		structure.add(BYTE, 1, "magic_1", null);
		structure.add(BYTE, 1, "magic_2", null);
		structure.add(BYTE, 2, "config", null);
		structure.add(BYTE, 4, "entrypoint", null);
		structure.add(BYTE, 4, "unused", null);
		structure.add(BYTE, 4, "iromTextSegmentLength", null);
		
		return structure;
	}
	
}