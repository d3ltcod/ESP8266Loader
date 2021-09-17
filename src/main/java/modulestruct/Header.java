package modulestruct;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;

public class Header {
	
	private byte magic;
	private byte segments;
	private byte flash_mode;
	private byte flash_size_free;
	private long entrypoint;
	
	public Header(BinaryReader reader) throws IOException {
		this.magic = reader.readNextByte();
		this.segments = reader.readNextByte();
		this.flash_mode = reader.readNextByte();
		this.flash_size_free = reader.readNextByte();
		this.entrypoint = reader.readNextInt();
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
	
}