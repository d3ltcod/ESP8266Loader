package modulestruct;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Header implements StructConverter{
	
	private byte magic;
	private byte segments;
	private byte flash_mode;
	private byte flash_size_free;
	private long entrypoint;

	public Header(byte magic, byte segments, byte flash_mode, byte flash_size_free, long entrypoint) {
		super();
		this.magic = magic;
		this.segments = segments;
		this.flash_mode = flash_mode;
		this.flash_size_free = flash_size_free;
		this.entrypoint = entrypoint;
	}

	public byte getMagic() {
		return magic;
	}

	public byte getSegments() {
		return segments;
	}

	public byte getFlash_mode() {
		return flash_mode;
	}

	public byte getFlash_size_free() {
		return flash_size_free;
	}

	public long getEntrypoint() {
		return entrypoint;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		
		structure.add(BYTE, 1, "magic", null);
		structure.add(BYTE, 1, "segments", "Number of segments");
		structure.add(BYTE, 1, "flash_mode", null);
		structure.add(BYTE, 1, "flash_size_free", null);
		structure.add(DWORD, 4, "entrypoint", "The entry function");
		
		return structure;
	}
	
}