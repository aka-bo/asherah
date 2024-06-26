package protectedmemory

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkProtectedMemorySecret_WithBytes(b *testing.B) {
	orig := []byte("thisismy32bytesecretthatiwilluse")
	copyBytes := make([]byte, len(orig))
	copy(copyBytes, orig)

	s, err := factory.New(orig)
	if assert.NoError(b, err) {
		defer s.Close()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				assert.NoError(b, s.WithBytes(func(bytes []byte) error {
					assert.Equal(b, copyBytes, bytes)
					return nil
				}))
			}
		})
	}
}

func BenchmarkProtectedMemorySecret_WithBytesFunc(b *testing.B) {
	orig := []byte("thisismy32bytesecretthatiwilluse")

	copyBytes := make([]byte, len(orig))
	copy(copyBytes, orig)

	s, err := factory.New(copyBytes)
	require.NoError(b, err)

	defer s.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := s.WithBytesFunc(func(bytes []byte) ([]byte, error) {
				assert.Equal(b, orig, bytes)
				return bytes, nil
			})
			assert.NoError(b, err)
		}
	})
}

func BenchmarkProtectedMemoryReader_ReadAll(b *testing.B) {
	orig := []byte("thisismy32bytesecretthatiwilluse")
	copyBytes := make([]byte, len(orig))
	copy(copyBytes, orig)

	s, err := factory.New(orig)
	require.NoError(b, err)

	defer s.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := s.NewReader()

			bytes, err := io.ReadAll(r)
			if assert.NoError(b, err) {
				assert.Equal(b, copyBytes, bytes)
			}
		}
	})
}

func BenchmarkProtectedMemoryReader_ReadFull(b *testing.B) {
	orig := []byte("thisismy32bytesecretthatiwilluse")
	copyBytes := make([]byte, len(orig))
	copy(copyBytes, orig)

	s, err := factory.New(orig)
	require.NoError(b, err)

	defer s.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, len(orig))

		for pb.Next() {
			r := s.NewReader()

			_, err := io.ReadFull(r, buf)
			if assert.NoError(b, err) {
				assert.Equal(b, copyBytes, buf)
			}
		}
	})
}

func BenchmarkProtectedMemoryReader_Read(b *testing.B) {
	orig := []byte("thisismy32bytesecretthatiwilluse")
	expected := make([]byte, len(orig))
	copy(expected, orig)

	s, err := factory.New(orig)
	require.NoError(b, err)

	defer s.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := s.NewReader()

			buf := make([]byte, len(orig))
			actual := make([]byte, len(orig))

			i := 0
			for {
				n, err := r.Read(buf)
				copy(actual[i:], buf[:n])
				i += n

				if err == io.EOF {
					break
				}
			}
			assert.Equal(b, expected, actual)
		}
	})
}
