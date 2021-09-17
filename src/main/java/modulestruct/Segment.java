package modulestruct;

import esp8266loader.Constants;

public class Segment {
	private int offset;
	private int size;
	private byte[] content;
	private String segmentName;
	
	public Segment(int offset, int size, byte[] content) {
		this.offset = offset;
		this.size = size;
		this.content = content;
		this.segmentName = calculateSegment(this.offset);
	}
	
	public int getOffset() {
		return offset;
	}

	public int getSize() {
		return size;
	}

	public byte[] getContent() {
		return content;
	}
	
	public String getSegmentName(){
		return segmentName;
	}
	
	private String calculateSegment(int loadAddress) {
		String result = "";
		
		if (loadAddress >= Constants.IROM_MAP_START && loadAddress < Constants.IROM_MAP_END)
			result="IROM";
		else if(loadAddress >= Constants.SPI_FLASH_START && loadAddress < Constants.SPI_FLASH_END)
			result="SPI_FLASH";
		else if(loadAddress >= Constants.IRAM_MAP_START && loadAddress < Constants.SPI_FLASH_START)
			result="IRAM";
		else if(loadAddress >= Constants.DRAM_MAP_START && loadAddress < Constants.DRAM_MAP_END)
			result="DRAM";
		else 
			result = "uknown";
			
		return result;
	}
	
}
