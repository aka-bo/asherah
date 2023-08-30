package integration_test

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/internal"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
)

const (
	product          = "enclibrary"
	service          = "asherah"
	partitionID      = "123456"
	staticKey        = "thisIsAStaticMasterKeyForTesting"
	payloadSizeBytes = 100
)

var (
	c         = aead.NewAES256GCM()
	metastore = newDelayedMetastore(10*time.Millisecond, 5*time.Millisecond)
	zipfSeed  = time.Now().UnixNano()
)

func getConfig() *appencryption.Config {
	policy := appencryption.NewCryptoPolicy(
		appencryption.WithRevokeCheckInterval(10 * time.Second),
	)

	policy.CreateDatePrecision = time.Second

	return &appencryption.Config{
		Policy:  policy,
		Product: product,
		Service: service,
	}
}

type delayedMetastore struct {
	m      *persistence.MemoryMetastore
	delay  time.Duration
	jitter time.Duration
}

func newDelayedMetastore(delay time.Duration, jitter time.Duration) *delayedMetastore {
	return &delayedMetastore{
		m:      persistence.NewMemoryMetastore(),
		delay:  delay,
		jitter: jitter,
	}
}

func (d *delayedMetastore) delayWithJitter() {
	ch := make(chan int)
	go func() {
		randJitter := int64(0)
		if d.jitter > 0 {
			randJitter = rand.Int63n(int64(d.jitter))
		}

		time.Sleep(d.delay + time.Duration(randJitter))

		ch <- 1
	}()

	<-ch
}

func (d *delayedMetastore) Load(ctx context.Context, keyID string, created int64) (*appencryption.EnvelopeKeyRecord, error) {
	d.delayWithJitter()

	return d.m.Load(ctx, keyID, created)
}

func (d *delayedMetastore) LoadLatest(ctx context.Context, keyID string) (*appencryption.EnvelopeKeyRecord, error) {
	d.delayWithJitter()

	return d.m.LoadLatest(ctx, keyID)
}

func (d *delayedMetastore) Store(ctx context.Context, keyID string, created int64, envelope *appencryption.EnvelopeKeyRecord) (bool, error) {
	d.delayWithJitter()

	return d.m.Store(ctx, keyID, created, envelope)
}

func TestMain(m *testing.M) {
	log.Printf("random seed: %d\n", zipfSeed)

	code := m.Run()

	os.Exit(code)
}

func Benchmark_Encrypt(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	factory := appencryption.NewSessionFactory(
		getConfig(),
		metastore,
		km,
		c,
	)
	defer factory.Close()

	randomBytes := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		randomBytes[i] = internal.GetRandBytes(payloadSizeBytes)
	}

	sess, _ := factory.GetSession(partitionID)
	defer sess.Close()

	b.ResetTimer()

	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bytes := randomBytes[b.N-1]

			if _, err := sess.Encrypt(ctx, bytes); err != nil {
				b.Error(err)
			}
		}
	})
}

func Benchmark_EncryptDecrypt_MultiFactorySamePartition(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			factory := appencryption.NewSessionFactory(
				getConfig(),
				metastore,
				km,
				c,
			)
			sess, _ := factory.GetSession(partitionID)
			randomBytes := internal.GetRandBytes(payloadSizeBytes)
			ctx := context.Background()

			drr, err := sess.Encrypt(ctx, randomBytes)
			if err != nil {
				b.Error(err)
			}

			data, _ := sess.Decrypt(ctx, *drr)
			assert.Equal(b, randomBytes, data)

			sess.Close()
			factory.Close()
		}
	})
}

func Benchmark_EncryptDecrypt_MultiFactoryUniquePartition(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	b.RunParallel(func(pb *testing.PB) {
		zipf := newZipf()

		for pb.Next() {
			factory := appencryption.NewSessionFactory(
				getConfig(),
				metastore,
				km,
				c,
			)
			sess, _ := factory.GetSession(fmt.Sprintf(partitionID+"_%d", zipf()))
			randomBytes := internal.GetRandBytes(payloadSizeBytes)
			ctx := context.Background()

			drr, err := sess.Encrypt(ctx, randomBytes)
			if err != nil {
				b.Error(err)
			}

			data, _ := sess.Decrypt(ctx, *drr)
			assert.Equal(b, randomBytes, data)

			sess.Close()
			factory.Close()
		}
	})
}

func Benchmark_EncryptDecrypt_SameFactoryUniquePartition(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	factory := appencryption.NewSessionFactory(
		getConfig(),
		metastore,
		km,
		c,
	)
	defer factory.Close()

	b.RunParallel(func(pb *testing.PB) {
		zipf := newZipf()

		for pb.Next() {
			partition := fmt.Sprintf(partitionID+"_%d", zipf())
			randomBytes := internal.GetRandBytes(payloadSizeBytes)

			sess, _ := factory.GetSession(partition)
			ctx := context.Background()

			drr, err := sess.Encrypt(ctx, randomBytes)
			if err != nil {
				b.Error(err)
			}

			data, _ := sess.Decrypt(ctx, *drr)
			assert.Equal(b, randomBytes, data)

			sess.Close()
		}
	})
}

// newZipf returns a function that returns a random uint64 value that follows a Zipf distribution.
// A Zipf distribution is used to simulate a real-world scenario where a small number of keys are
// used more frequently than others.
func newZipf() func() uint64 {
	zipfS := 1.0001
	v := 10.0
	n := appencryption.DefaultSessionCacheMaxSize * 32

	z := rand.NewZipf(rand.New(rand.NewSource(zipfSeed)), zipfS, v, uint64(n))

	return z.Uint64
}

func Benchmark_EncryptDecrypt_SameFactoryUniquePartition_WithSessionCache(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	config := getConfig()
	config.Policy.CacheSessions = true
	config.Policy.SessionCacheDuration = 20 * time.Second
	config.Policy.SessionCacheMaxSize = appencryption.DefaultSessionCacheMaxSize

	factory := appencryption.NewSessionFactory(
		config,
		metastore,
		km,
		c,
	)

	defer factory.Close()

	b.RunParallel(func(pb *testing.PB) {
		zipf := newZipf()

		for pb.Next() {
			partition := fmt.Sprintf("%d", zipf())
			randomBytes := internal.GetRandBytes(payloadSizeBytes)

			sess, _ := factory.GetSession(partition)
			ctx := context.Background()

			drr, err := sess.Encrypt(ctx, randomBytes)
			if err != nil {
				b.Error(err)
			}

			data, _ := sess.Decrypt(ctx, *drr)
			assert.Equal(b, randomBytes, data)

			sess.Close()
		}
	})
}

func Benchmark_EncryptDecrypt_SameFactorySamePartition(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	factory := appencryption.NewSessionFactory(
		getConfig(),
		metastore,
		km,
		c,
	)
	defer factory.Close()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			randomBytes := internal.GetRandBytes(payloadSizeBytes)

			sess, _ := factory.GetSession(partitionID)
			ctx := context.Background()

			drr, err := sess.Encrypt(ctx, randomBytes)
			if err != nil {
				b.Error(err)
			}

			data, _ := sess.Decrypt(ctx, *drr)
			assert.Equal(b, randomBytes, data)

			sess.Close()
		}
	})
}

func Benchmark_EncryptDecrypt_SameFactorySamePartition_WithSessionCache(b *testing.B) {
	km, err := kms.NewStatic(staticKey, c)
	assert.NoError(b, err)

	defer km.Close()

	config := getConfig()
	config.Policy.CacheSessions = true
	config.Policy.SessionCacheDuration = 20 * time.Second
	config.Policy.SessionCacheMaxSize = 10

	factory := appencryption.NewSessionFactory(
		config,
		metastore,
		km,
		c,
	)
	defer factory.Close()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			randomBytes := internal.GetRandBytes(payloadSizeBytes)

			sess, _ := factory.GetSession(partitionID)
			ctx := context.Background()

			drr, err := sess.Encrypt(ctx, randomBytes)
			if err != nil {
				b.Error(err)
			}

			data, _ := sess.Decrypt(ctx, *drr)
			assert.Equal(b, randomBytes, data)

			sess.Close()
		}
	})
}
