type Section = {
  virtualAddress: number;
  virtualSize: number;
  rawPointer: number;
  rawSize: number;
};

type ResourceDataEntry = {
  rva: number;
  size: number;
};

type GroupIconEntry = {
  width: number;
  height: number;
  colorCount: number;
  planes: number;
  bitCount: number;
  bytesInRes: number;
  id: number;
};

type ResourceDirectoryEntry = {
  id: number | null;
  name: string | null;
  isDirectory: boolean;
  offset: number;
};

function readUtf16(view: DataView, offset: number, length: number): string {
  let value = '';
  for (let index = 0; index < length; index += 1) {
    const code = view.getUint16(offset + index * 2, true);
    if (code === 0) {
      break;
    }
    value += String.fromCharCode(code);
  }
  return value;
}

function parsePeSections(view: DataView): {
  resourceRva: number;
  sections: Section[];
} {
  if (view.byteLength < 0x40) {
    throw new Error('File too small');
  }

  if (view.getUint16(0, true) !== 0x5a4d) {
    throw new Error('Missing MZ header');
  }

  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 0x18 > view.byteLength) {
    throw new Error('Invalid PE header offset');
  }

  if (view.getUint32(peOffset, true) !== 0x00004550) {
    throw new Error('Missing PE signature');
  }

  const numberOfSections = view.getUint16(peOffset + 6, true);
  const optionalHeaderSize = view.getUint16(peOffset + 20, true);
  const optionalHeaderOffset = peOffset + 24;
  const magic = view.getUint16(optionalHeaderOffset, true);

  let dataDirectoryOffset: number;
  if (magic === 0x10b) {
    dataDirectoryOffset = optionalHeaderOffset + 96;
  } else if (magic === 0x20b) {
    dataDirectoryOffset = optionalHeaderOffset + 112;
  } else {
    throw new Error(`Unsupported PE optional header magic: 0x${magic.toString(16)}`);
  }

  const resourceRva = view.getUint32(dataDirectoryOffset + 2 * 8, true);
  if (!resourceRva) {
    throw new Error('No resource directory found');
  }

  const sections: Section[] = [];
  const sectionOffset = optionalHeaderOffset + optionalHeaderSize;
  for (let index = 0; index < numberOfSections; index += 1) {
    const offset = sectionOffset + index * 40;
    const virtualSize = view.getUint32(offset + 8, true);
    const virtualAddress = view.getUint32(offset + 12, true);
    const rawSize = view.getUint32(offset + 16, true);
    const rawPointer = view.getUint32(offset + 20, true);

    sections.push({
      virtualAddress,
      virtualSize,
      rawPointer,
      rawSize,
    });
  }

  return { resourceRva, sections };
}

function rvaToOffset(rva: number, sections: Section[]): number {
  for (const section of sections) {
    const sectionSize = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + sectionSize) {
      return section.rawPointer + (rva - section.virtualAddress);
    }
  }

  throw new Error(`RVA 0x${rva.toString(16)} is outside the file-backed sections`);
}

function readResourceDirectoryEntries(
  view: DataView,
  baseOffset: number,
  directoryOffset: number,
): ResourceDirectoryEntry[] {
  const offset = baseOffset + directoryOffset;
  const namedEntries = view.getUint16(offset + 12, true);
  const idEntries = view.getUint16(offset + 14, true);
  const totalEntries = namedEntries + idEntries;
  const entries: ResourceDirectoryEntry[] = [];

  for (let index = 0; index < totalEntries; index += 1) {
    const entryOffset = offset + 16 + index * 8;
    const nameValue = view.getUint32(entryOffset, true);
    const dataValue = view.getUint32(entryOffset + 4, true);
    const isNameString = (nameValue & 0x80000000) !== 0;
    const isDirectory = (dataValue & 0x80000000) !== 0;
    let id: number | null = null;
    let name: string | null = null;

    if (isNameString) {
      const nameOffset = baseOffset + (nameValue & 0x7fffffff);
      const charCount = view.getUint16(nameOffset, true);
      name = readUtf16(view, nameOffset + 2, charCount);
    } else {
      id = nameValue & 0xffff;
    }

    entries.push({
      id,
      name,
      isDirectory,
      offset: dataValue & 0x7fffffff,
    });
  }

  return entries;
}

function readResourceDataEntry(
  view: DataView,
  baseOffset: number,
  dataEntryOffset: number,
): ResourceDataEntry {
  const offset = baseOffset + dataEntryOffset;
  return {
    rva: view.getUint32(offset, true),
    size: view.getUint32(offset + 4, true),
  };
}

function parseGroupIconEntries(blob: Uint8Array): GroupIconEntry[] {
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  if (view.getUint16(0, true) !== 0 || view.getUint16(2, true) !== 1) {
    throw new Error('Invalid group icon resource');
  }

  const count = view.getUint16(4, true);
  const entries: GroupIconEntry[] = [];

  for (let index = 0; index < count; index += 1) {
    const offset = 6 + index * 14;
    if (offset + 14 > blob.byteLength) {
      break;
    }

    entries.push({
      width: view.getUint8(offset) || 256,
      height: view.getUint8(offset + 1) || 256,
      colorCount: view.getUint8(offset + 2),
      planes: view.getUint16(offset + 4, true),
      bitCount: view.getUint16(offset + 6, true),
      bytesInRes: view.getUint32(offset + 8, true),
      id: view.getUint16(offset + 12, true),
    });
  }

  return entries;
}

function buildIconBlob(entries: Array<GroupIconEntry & { data: Uint8Array }>): Blob {
  const headerSize = 6 + entries.length * 16;
  const totalSize = headerSize + entries.reduce((sum, entry) => sum + entry.data.byteLength, 0);
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  view.setUint16(0, 0, true);
  view.setUint16(2, 1, true);
  view.setUint16(4, entries.length, true);

  let dataOffset = headerSize;
  entries.forEach((entry, index) => {
    const entryOffset = 6 + index * 16;
    view.setUint8(entryOffset, entry.width === 256 ? 0 : entry.width);
    view.setUint8(entryOffset + 1, entry.height === 256 ? 0 : entry.height);
    view.setUint8(entryOffset + 2, entry.colorCount);
    view.setUint8(entryOffset + 3, 0);
    view.setUint16(entryOffset + 4, entry.planes, true);
    view.setUint16(entryOffset + 6, entry.bitCount, true);
    view.setUint32(entryOffset + 8, entry.data.byteLength, true);
    view.setUint32(entryOffset + 12, dataOffset, true);
    bytes.set(entry.data, dataOffset);
    dataOffset += entry.data.byteLength;
  });

  return new Blob([buffer], { type: 'image/x-icon' });
}

export function extractExeIconUrl(arrayBuffer: ArrayBuffer): string | null {
  const view = new DataView(arrayBuffer);
  const { resourceRva, sections } = parsePeSections(view);
  const resourceBase = rvaToOffset(resourceRva, sections);
  const rootEntries = readResourceDirectoryEntries(view, resourceBase, 0);

  const typeDirectory = rootEntries.find((entry) => entry.id === 14 && entry.isDirectory);
  if (!typeDirectory) {
    return null;
  }

  const groupEntries: Array<GroupIconEntry & { data: Uint8Array }> = [];
  const groupIds = readResourceDirectoryEntries(view, resourceBase, typeDirectory.offset);

  for (const groupId of groupIds) {
    if (!groupId.isDirectory) {
      continue;
    }

    const langEntries = readResourceDirectoryEntries(view, resourceBase, groupId.offset);
    const dataEntry = langEntries.find((entry) => !entry.isDirectory);
    if (!dataEntry) {
      continue;
    }

    const resourceData = readResourceDataEntry(view, resourceBase, dataEntry.offset);
    const dataOffset = rvaToOffset(resourceData.rva, sections);
    const groupBlob = new Uint8Array(arrayBuffer.slice(dataOffset, dataOffset + resourceData.size));
    const parsedGroupEntries = parseGroupIconEntries(groupBlob);

    const iconTypeDirectory = rootEntries.find((entry) => entry.id === 3 && entry.isDirectory);
    if (!iconTypeDirectory) {
      return null;
    }

    const iconIdEntries = readResourceDirectoryEntries(view, resourceBase, iconTypeDirectory.offset);
    const iconMap = new Map<number, Uint8Array>();

    for (const iconIdEntry of iconIdEntries) {
      if (!iconIdEntry.isDirectory || iconIdEntry.id === null) {
        continue;
      }

      const iconLangEntries = readResourceDirectoryEntries(view, resourceBase, iconIdEntry.offset);
      const iconDataEntry = iconLangEntries.find((entry) => !entry.isDirectory);
      if (!iconDataEntry) {
        continue;
      }

      const iconResourceData = readResourceDataEntry(view, resourceBase, iconDataEntry.offset);
      const iconDataOffset = rvaToOffset(iconResourceData.rva, sections);
      iconMap.set(
        iconIdEntry.id,
        new Uint8Array(arrayBuffer.slice(iconDataOffset, iconDataOffset + iconResourceData.size)),
      );
    }

    for (const entry of parsedGroupEntries) {
      const data = iconMap.get(entry.id);
      if (data) {
        groupEntries.push({ ...entry, data });
      }
    }

    if (groupEntries.length > 0) {
      break;
    }
  }

  if (groupEntries.length === 0) {
    return null;
  }

  const iconBlob = buildIconBlob(groupEntries);
  return URL.createObjectURL(iconBlob);
}
