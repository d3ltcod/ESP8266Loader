package esp8266loader;

public class Constants {
	public final static byte ESP_MAGIC_BASE_V1 = (byte) 0xE9;
	public final static byte ESP_MAGIC_BASE_V2 = (byte) 0xEA;
	public final static byte ESP_MAGIC_BASE_V2_2 = (byte) 0x04;
	public final static int USER_ROM_DATA_START = 0x3FFE8000;
	public final static int USER_ROM_DATA_END = 0x3FFFFFFF;
    public final static int USER_ROM_CODE_START = 0x40100000;
	public final static int IROM_START = 0x40000000;
	public final static int IROM_END = 0x40100000;
}
