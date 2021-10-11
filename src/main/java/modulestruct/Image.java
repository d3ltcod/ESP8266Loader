package modulestruct;

import java.util.List;
import esp8266loader.Constants;
import ghidra.app.util.bin.BinaryReader;
import java.io.IOException;
import java.util.ArrayList;

public class Image {
	
	private Header header;
	private int version;
	private List<Segment> segments = new ArrayList<Segment>();
	private BinaryReader reader;
	
	public Image(BinaryReader reader) throws IOException {
		this.reader = reader;
//		this.header = readHeader();
//		addSegments(this.header.getSegments());
		
		this.version = checkVersion();
		this.reader.setPointerIndex(0x1000);
		
		if (version == 2) stepsForImageV2();
		
		this.header = readHeader();
		addSegments(this.header.getSegments());
	}
	
	public Header getHeader() {
		return header;
	}

	public List<Segment> getSegments() {
		return segments;
	}
	
	private void stepsForImageV2() throws IOException {
		this.reader.setPointerIndex((0x1000));
		HeaderV2 h2 = readHeaderV2();
		
		int iromLength = (int)h2.getIromTextSegmentLength();
		
		byte[] content = this.reader.readNextByteArray(iromLength);
		Segment s = new Segment(Constants.IROM_START, iromLength, content);
		segments.add(s);
		
		this.reader.setPointerIndex((0x1000+0x10+iromLength));
	}
	
	private Header readHeader() throws IOException {
		byte magic = this.reader.readNextByte();
		byte numberSegments = this.reader.readNextByte();
		byte flash_mode = this.reader.readNextByte();
		byte flash_size_free = this.reader.readNextByte();
		long entrypoint = this.reader.readNextInt();
		
		return new Header(magic, numberSegments, flash_mode, flash_size_free, entrypoint);
	}
	
	private HeaderV2 readHeaderV2() throws IOException {
		byte magic_1 = this.reader.readNextByte();
		byte magic_2 = this.reader.readNextByte();
		short config = this.reader.readNextShort();
		long entrypoint = this.reader.readNextInt();
		long unused = this.reader.readNextInt();
		long iromTextSegmentLength = this.reader.readNextInt();
		
		return new HeaderV2(magic_1, magic_2, config, entrypoint, unused, iromTextSegmentLength);
	}
	
	private Segment readSegment() throws IOException {
		int offset = this.reader.readNextInt();
		int size = this.reader.readNextInt();	
		byte[] content = this.reader.readNextByteArray(size);
				
		return new Segment(offset, size, content);
	}
	
	private void addSegments(byte numberSegments) throws IOException {
		for(int i=0; i < numberSegments; ++i) 
			this.segments.add(readSegment());
		
	}
	
	private int checkVersion() throws IOException {
		this.reader.setPointerIndex(0x1000);
		byte mn = this.reader.readNextByte();

		if(mn == Constants.ESP_MAGIC_BASE_V1) return 1;
		else if (mn == Constants.ESP_MAGIC_BASE_V2 || mn == Constants.ESP_MAGIC_BASE_V2_2) return 2;
		else throw new IOException("This is not an ESP8266 file");
	}
}
