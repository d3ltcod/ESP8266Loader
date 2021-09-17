package modulestruct;

public class Header {
	
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
	
}